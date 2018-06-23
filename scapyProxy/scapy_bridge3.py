"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

from Tkinter import *
from scapy.all import *
import os
import threading
from multiprocessing import Pipe
import time
from scapyProxy.GuiUtils import VerticalScrolledFrame
from socket import gaierror
import chardet
import interceptor
from StringIO import StringIO
import sys
import tkFileDialog
from ScrolledText import ScrolledText


class ScapyBridge(object):
    
    def __init__(self, tbmg_, is_outgoing_=False):
        # output catches outgoing packets, input from other machines, and forward for mitm
        #self.iptablesr = "iptables -A OUTPUT -j NFQUEUE --queue-num 0; iptables -A FORWARD -j NFQUEUE --queue-num 0; iptables -A INPUT -j NFQUEUE --queue-num 0"
        #self.iptablesr = ""#""iptables -t nat -A PREROUTING -j NFQUEUE --queue-num 2"
        #self.iptablesr = 'iptables -I INPUT 1 -j NFQUEUE --queue-balance 0:2'
        self.is_outgoing = is_outgoing_
        self.iptablesr = ''
        if self.is_outgoing:
            self.iptablesr = 'iptables -I OUTPUT 1 -j NFQUEUE --queue-balance 0:19; iptables -I FORWARD 1 -j NFQUEUE --queue-balance 0:19'
        else:
            self.iptablesr = 'iptables -I INPUT 1 -j NFQUEUE --queue-balance 20:39'
        
        self.tbmg = tbmg_
        self.q = None
        self.status = False
        self.filter = None
        self.parent_conn, self.child_conn = Pipe()
        self.pcapfile = ''
        self.intercepting = False
        self.gui_layers = {}  # gui_layers['IP'] = [(Label(text=layer),Label(text=feild_name),Entry(text=feild_value)),(L,E),...]
        self.current_pack = None
        self.intercepter = interceptor.Interceptor()
        self.packet_queue = [] #[x] = (prio#, scapy_packet)
        self.display_lock = Lock()
        self.pack_num_counter=1
        self.skip_to_pack_num=0#use me to skip ahead
        self.pack_view_packs =[]
        self.ether_pass = []
        self.arp_stop = False
        self.arp_sniff_thread = Thread(target=self.arpSniff)
        self.arp_sniff_thread.setDaemon(True)
        
        
    #only run in one scapy_bridge instance
    def loadPCAP(self):
        def popUP(i):
            print 'CLICKED PACKET:',str(i)
            pkt = self.pack_view_packs[i]
            popup = Toplevel()
            popup.title = pkt.summary()
            pack_text = self._packet_disect_nointercept(pkt)
            replaceIncoming = Button(popup, text='Replace Incoming',command=lambda pack=pkt: self.tbmg.scapybridgeR._packet_disect_intercept(pack,True))
            replaceIncoming.grid(row=6, column=5)
            replaceOutgoing = Button(popup, text='Replace Outgoing',command=lambda pack=pkt: self.tbmg.scapybridgeS._packet_disect_intercept(pack,True))
            replaceOutgoing.grid(row=6, column=6)
            msg = ScrolledText(popup)
            #scroller = Scrollbar(popup)
            #scroller.config(command=msg.yview)
            #msg.config(yscrollcommand=scroller.set)
            msg.grid(row=0,column=0,columnspan=2)
            replaceOutgoing.grid(row=1,column=0)
            replaceIncoming.grid(row=1,column=1)
            #scroller.pack()
            msg.insert(END, pack_text)
            #self.tbmg.replaceIncoming.configure(command=lambda pack=pkt: self.tbmg.scapybridgeR._packet_disect_intercept(pack))
            #self.tbmg.replaceOutgoing.configure(command=lambda pack=pkt: self.tbmg.scapybridgeS._packet_disect_intercept(pack))
        self.pack_view_packs = []
        for button in self.tbmg.pack_view.interior.grid_slaves():
            button.destroy()
        i = 0
        f = tkFileDialog.asksaveasfile(mode='r', defaultextension=".pcap")
        name = f.name
        f.close()
        packets = rdpcap(name)
        for p in packets:
            print (i, p.summary())
            b = Button(self.tbmg.pack_view.interior, text=p.summary(), width=50, command=lambda j=i: popUP(j))
            #TODO add popup w/ packet details
            b.grid(row=i, column=0)
            self.pack_view_packs.append(p)
            i = i+1
        f.close()
        
    def arpHelper(self,pkt):
        im_the_dst = bool(str(pkt['ARP'].hwdst) in self.tbmg.macs)
        if not self.is_outgoing:
            if im_the_dst:
                t = Thread(target=self.callback, args=(raw(pkt),None,None,None))
                t.setDaemon(True)
                t.start()
        elif not im_the_dst:
            t = Thread(target=self.callback, args=(raw(pkt), None, None, None))
            t.setDaemon(True)
            t.start()
    
    def arpSniff(self):
        #TODO seperate in/out arps
        a = sniff(prn=self.arpHelper, filter='arp',stop_filter=lambda x:self.arp_stop==True)
        print('stopped apr sniff')
    
    def sendDrop(self):
        if self.intercepting:
            self.parent_conn.send('drop')
    
    def sendRawUpdate(self):
        if self.intercepting:
            if self.is_outgoing:
                text = str(self.tbmg.rawtextS.get('0.0', END)).strip()
            else:
                text = str(self.tbmg.rawtextR.get('0.0', END)).strip()
            print 'updating to:', text
            self.parent_conn.send('raw')
            self.parent_conn.send(text)
    
    def sendDisectUpdate(self):
        if not self.intercepting:
            return
        #skip if no GUI
        if self.is_outgoing:
            if not self.gui_layers or len(self.tbmg.disectlistS.interior.grid_slaves()) < 2:
                return
        else:
            if not self.gui_layers or len(self.tbmg.disectlistR.interior.grid_slaves()) < 2:
                return
        #update packet based on GUI
        for layer in self.gui_layers:
            if layer and layer in self.current_pack:
                for pair in self.gui_layers[layer]:
                    type1 = getattr(self.current_pack[layer], pair[1].cget('text'))  # correct type for feild
                    type2 = None
                    value = None
                    try:
                        value = str(int(pair[2].get())).strip()
                    except:
                        value = str(pair[2].get())
                        try:
                            value = '"' + value.encode('utf8') + '"'
                        except:  # should only happen on custom input
                            print 'oddball:', value
                            if type1 == int:
                                value = int(value.encode('hex'), 16)
                            else:
                                value = '"' + value.decode('hex') + '"'  # assuming unicode
                    # TODO add protocol exceptions here!
                    try:
                        if type(value) == str and type1 == str:
                            if int(value[1:-1], 16):
                                value = '"' + value[1:-1].decode('hex') + '"'
                                print('found HEX', value)
                    except Exception:
                        pass
                        # print value,'not HEX',e
                    if '['in value and ']'in value:#type(value) == str and len(value) >= 4 and value[1] == '[' and value[-2] == ']' and type1 == type([]):
                        #print 'found array type:'+value
                        value = value[1:-1]
                    elif value == '"None"':
                        if type1 == type(None):
                            continue
                        if type1 == int:
                            value = '0'
                        else:
                            value = 'None'
                    elif value == '""':
                        value = 'None'
                    if layer == 'Raw' and pair[1].cget('text') == 'load':  # ping 8.8.4.4
                        try:
                            if not self.current_pack[layer].load == value[1:-1].decode('hex'):
                                print("FOUND CHANGE in RAW!!!", value, value.encode('hex'))
                                print(self.current_pack['Raw'].load, self.current_pack['Raw'].load.encode('hex'))
                                print('------------------')
                                continue  # use default val
                            self.current_pack['Raw'].load = value[1:-1].decode('hex')
                            continue
                        except:
                            pass #non hex decodable
                    #('checking if equal:', 'self.current_pack[\'DNS\'].qd == "\ndiscordapp\x03com"')
                    #self.current_pack['DNS'].qd == "
                    # TODO add protocol exceptions here!
                    #set value to packet
                    #execute = "self.current_pack['" + layer + "']." + pair[1].cget('text') + " = " + value
                    #print('setting:', execute)
                    try:
                        if getattr(self.current_pack[layer], pair[1].cget('text')) != eval(value):
                            execute = "self.current_pack['" + layer + "']." + pair[1].cget('text') + " = " + value
                            #print('setting:', execute)
                            #print 'oldval->',getattr(self.current_pack[layer],pair[1].cget('text')),type(getattr(self.current_pack[layer],pair[1].cget('text')))
                            setattr(self.current_pack[layer], pair[1].cget('text'), eval(value))
                            print 'newval->',getattr(self.current_pack[layer],pair[1].cget('text')),type(getattr(self.current_pack[layer],pair[1].cget('text')))
                    except Exception, e:
                        print 'setattr err:',e,'->',"self.current_pack['" + layer + "']." + pair[1].cget('text') + " = " + value
        r = raw(self.current_pack)
        print('producing from disect:', r.encode('hex'))
        if self.status and self.intercepting:
            self.parent_conn.send(r)
        else:
            print 'going to send...'
            sendp(self.current_pack)
            print 'send packet'
        self.gui_layers = None
        self.clearDisect()
        self.clearRaw()
    
    def clearDisect(self):
        if self.is_outgoing:
            for w in self.tbmg.disectlistS.interior.grid_slaves():
                w.destroy()
        else:
            for w in self.tbmg.disectlistR.interior.grid_slaves():
                w.destroy()
    
    def clearRaw(self):
        if self.is_outgoing:
            self.tbmg.rawtextS.delete(1.0, END)
        else:
            self.tbmg.rawtextR.delete(1.0, END)
    
    def _packet_disect_intercept(self, pack, overwrite_current_pack=False):
        self.clearDisect()
        if overwrite_current_pack:
            self.current_pack = pack
        self.gui_layers = {}
        rownum = 1
        #$pack.show()
        if self.is_outgoing:
            for i in range(10):
                try:
                    l = pack.getlayer(i)
                    if not l:
                        continue
                    self.gui_layers[l.name] = []
                    
                    layer = Label(self.tbmg.disectlistS.interior, text=l.name)
                    layer.grid(row=rownum, column=0)
                    rownum += 1
                    if l.name == 'Ethernet' or l.name == 'Ether':
                        label = Label(self.tbmg.disectlistS.interior, text='src')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistS.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].src).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                        
                        label = Label(self.tbmg.disectlistS.interior, text='dst')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistS.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].dst).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                        
                        label = Label(self.tbmg.disectlistS.interior, text='type')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistS.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].type).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                        continue
                        
                    for f in l.fields:
                        label = Label(self.tbmg.disectlistS.interior, text=str(f))
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistS.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        try:
                            entry.insert(0, str(l.fields[f]).encode('utf8'))
                        except:
                            #print('FOUND ODD ENCODING:', chardet.detect(str(l.fields[f])))
                            entry.insert(0, str(l.fields[f]).encode('hex'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                except Exception, e:
                    print 'print disect yes intercpet error', e
                    break
        else:
            for i in range(10):
                try:
                    l = pack.getlayer(i)
                    if not l:
                        continue
                    self.gui_layers[l.name] = []
            
                    layer = Label(self.tbmg.disectlistR.interior, text=l.name)
                    layer.grid(row=rownum, column=0)
                    rownum += 1
                    if l.name == 'Ethernet' or l.name == 'Ether':
                        label = Label(self.tbmg.disectlistR.interior, text='src')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistR.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].src).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                
                        label = Label(self.tbmg.disectlistR.interior, text='dst')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistR.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].dst).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                
                        label = Label(self.tbmg.disectlistR.interior, text='type')
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistR.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        entry.insert(0, str(pack[0].type).encode('utf8'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                        continue
            
                    for f in l.fields:
                        label = Label(self.tbmg.disectlistR.interior, text=str(f))
                        label.grid(row=rownum, column=1)
                        entry = Entry(self.tbmg.disectlistR.interior, width=30)
                        entry.grid(row=rownum, column=2)
                        try:
                            entry.insert(0, str(l.fields[f]).encode('utf8'))
                        except:
                            # print('FOUND ODD ENCODING:', chardet.detect(str(l.fields[f])))
                            entry.insert(0, str(l.fields[f]).encode('hex'))
                        self.gui_layers[l.name].append((layer, label, entry))
                        rownum += 1
                except Exception, e:
                    print 'print disect yes intercpet error', e
                    break
    
    def _packet_disect_nointercept(self, pack):
        capture = StringIO()
        save_stdout = sys.stdout
        sys.stdout = capture
        pack.show()
        sys.stdout = save_stdout
        return capture.getvalue()+'\n----------------------------------\n'
    
    def interceptToggle(self):
        self.intercepting = not self.intercepting
        if self.is_outgoing:
            def addnointercptGUI():
                self.tbmg.disecttextS = ScrolledText(self.tbmg.page5, height=30, width=60)
                self.tbmg.disecttextS.grid(row=3, column=1)
                self.tbmg.disecttextS.insert(END, 'DISECT\n---\n')
            
            def addintercptGUI():
                self.tbmg.disectlistS = VerticalScrolledFrame(self.tbmg.page5, height=30, width=50)
                self.tbmg.disectlistS.grid(row=3, column=1)
                self.tbmg.disectLableS = Label(self.tbmg.disectlistS.interior, text='DISECT VIEW\n----\n')
                self.tbmg.disectLableS.grid(row=0, column=0)
            
            if self.intercepting:
                if self.tbmg.disecttextS:
                    self.tbmg.disecttextS.destroy()
                    self.tbmg.disecttextS = None
                if not (self.tbmg.disectlistS and self.tbmg.disectLableS):
                    addintercptGUI()
            else:
                if self.tbmg.disectlistS or self.tbmg.disectLableS:
                    self.tbmg.disectlistS.destroy()
                    self.tbmg.disectlistS = None
                    self.tbmg.disectLableS.destroy()
                    self.tbmg.disectLableS = None
                if not self.tbmg.disecttextS:
                    addnointercptGUI()
        else:
            def addnointercptGUI():
                self.tbmg.disecttextR = ScrolledText(self.tbmg.page5, height=30, width=60)
                self.tbmg.disecttextR.grid(row=5, column=1)
                self.tbmg.disecttextR.insert(END, 'DISECT\n---\n')
    
            def addintercptGUI():
                self.tbmg.disectlistR = VerticalScrolledFrame(self.tbmg.page5, height=30, width=50)
                self.tbmg.disectlistR.grid(row=5, column=1)
                self.tbmg.disectLableR = Label(self.tbmg.disectlistR.interior, text='DISECT VIEW\n----\n')
                self.tbmg.disectLableR.grid(row=0, column=0)
    
            if self.intercepting:
                if self.tbmg.disecttextR:
                    self.tbmg.disecttextR.destroy()
                    self.tbmg.disecttextR = None
                if not (self.tbmg.disectlistR and self.tbmg.disectLableR):
                    addintercptGUI()
            else:
                if self.tbmg.disectlistR or self.tbmg.disectLableR:
                    self.tbmg.disectlistR.destroy()
                    self.tbmg.disectlistR = None
                    self.tbmg.disectLableR.destroy()
                    self.tbmg.disectLableR = None
                if not self.tbmg.disecttextR:
                    addnointercptGUI()
        print 'intercpet is now', self.intercepting
        if not self.intercepting:
            self.parent_conn.send('accept')
            self.clearRaw()
            try:
                self.clearDisect()
            except:
                pass
    
    def proxyToggle(self):
        #print(not self.status)
        self.status = not self.status
        if self.status:
            try:
                print("Adding iptable rules :",self.iptablesr)
                os.system(self.iptablesr)
                self.intercepter = interceptor.Interceptor()
                try:
                    print 'about to start proxy'
                    self.arp_stop = False
                    self.arp_sniff_thread.start()
                    if self.is_outgoing:
                        self.intercepter.start(self.callback, queue_ids=range(20))
                    else:
                        self.intercepter.start(self.callback, queue_ids=range(20, 40))
                    print ('moving after proxy start')
                except Exception, e:
                    print 'COUNDT START PROXY',e
                    print("Flushing iptables.")
                    # This flushes everything, you might wanna be careful
                    # may want a way to restore tables after
                    os.system('iptables -F')
                    os.system('iptables -X')
            except Exception, e:
                print 'start proxy err', e
        else:
            try:
                #TODO change to accept the exact amount of packs
                self.arp_stop = True
                print 'mass accept packs'
                #clean gui/packs
                if self.intercepting:
                    for i in range(40):
                        self.parent_conn.send('accept')
                    time.sleep(.3)
                    while self.child_conn.poll():
                        self.child_conn.recv()
                    self.clearRaw()
                    self.clearDisect()
                #stop proxy
                print('flushing...')
                os.system('iptables -F')
                os.system('iptables -X')
                print 'stoping proxy'
                self.intercepter.stop()
                
            except Exception, e:
                print 'proxy err:',e
                pass

    # ran from seperate process
    def callback(self, ll_data, ll_proto_id, data, ctx):
        def skipAhead(dst_num):
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            print 'SKIIIIIIIIIIIIIIIIIP!!!!!!!!!! to ', str(dst_num)
            self.skip_to_pack_num = dst_num
            self.parent_conn.send('accept')
        # Here is where the magic happens.
        if not self.status:
            print 'I should not be on...'
            return data, interceptor.NF_DROP
        num = self.pack_num_counter
        self.pack_num_counter +=1 # may need to make this thread safe
        if data:
            packet = Ether(ll_data) / IP(data)
            org = Ether(ll_data) / IP(data)
        else:
            packet = Ether(ll_data)
            org =Ether(ll_data)
        
        if packet in self.ether_pass:#arp should not catch here...
            print 'FOUND SENT ETH CHANGE PACKET - ACCEPTING'
            packet.show()
            self.ether_pass.remove(packet)
            return data, interceptor.NF_ACCEPT
        dofilter = False  # show package in gui when = True
        if self.filter:
            try:
                dofilter = bool(sniff(offline=packet, filter=self.filter))
                if not dofilter:
                    if data:
                        return data, interceptor.NF_ACCEPT
                    elif self.intercepting:
                        #sendp(packet)
                        return
            except Exception, e:
                print 'Filter err:', self.filter, e
                if data:
                    return data, interceptor.NF_ACCEPT
                elif self.intercepting:
                    #sendp(packet)
                    return
        print("Got a packet " + str(num))  # +":", packet.summary())
        # list packet arival
        if self.intercepting:
            id = time.time()  # self.getID()
            if self.is_outgoing:
                button = Button(self.tbmg.netqueueframeS.interior,text=str(num) + ":" + packet.summary(),
                                width="80", command=lambda: skipAhead(num))
            else:
                button = Button(self.tbmg.netqueueframeR.interior, text=str(num) + ":" + packet.summary(),
                                width="80", command=lambda: skipAhead(num))
            button.pack()
            self.packet_queue.append([1, packet, id, button])
        
        # lock - one at a time get to render,
        print 'want lock'
        self.display_lock.acquire()
        print 'got lock for ',str(num)
        if not self.status:
            print 'I should not be on...'
            try:
                button.destroy()
            except:
                pass
            self.display_lock.release()
            if data:
                return data, interceptor.NF_ACCEPT
            elif self.intercepting:
                #sendp(packet)
                return
        #if self.skip_to_pack_num:
        if num < self.skip_to_pack_num:
            print 'skipping! im at',str(num)
            button.destroy()
            self.display_lock.release()
            if data:
                return data, interceptor.NF_ACCEPT
            else:
                #sendp(packet)
                return
        elif num == self.skip_to_pack_num:
            print 'hit num.im at',str(num)
            self.skip_to_pack_num=0
        
        self.current_pack = packet
        if self.intercepting:
            print 'intercepting'
            if self.filter and not dofilter:
                print 'intercept, but not in filter'
                if self.pcapfile:
                    wrpcap(self.pcapfile, org, append=True)
                    wrpcap(self.pcapfile[:-5] + '_mod.pcap', org, append=True)
                self.display_lock.release()
                if data:
                    return data, interceptor.NF_ACCEPT
                elif self.intercepting:
                    #sendp(packet)
                    return
            
            #display packet
            self.clearDisect()
            self.clearRaw()
            self._packet_disect_intercept(self.current_pack)
            if self.is_outgoing:
                self.tbmg.rawtextS.insert('0.0', str(raw(self.current_pack)).encode('hex'))
            else:
                self.tbmg.rawtextR.insert('0.0', str(raw(self.current_pack)).encode('hex'))
            
            #recive data from GUI
            
            recv = self.child_conn.recv()
            if recv == 'drop':
                print 'DROPING'
                self.display_lock.release()
                button.destroy()
                #TODO efficently delte self from packet queue
                if data:
                    return data, interceptor.NF_DROP
            elif recv == 'accept':
                print "ACCEPTING",str(num)
                try:
                    self.clearDisect()
                except:
                    pass
                self.clearRaw()
                self.display_lock.release()
                button.destroy()
                if data:
                    return data, interceptor.NF_ACCEPT
                elif self.intercepting:
                    #sendp(packet)
                    return
            elif recv == 'raw':
                recv = str(self.child_conn.recv())
                #TODO make more definite way...
                if data:
                    self.current_pack = Ether(recv[:recv.index('450000')].decode('hex'))/ IP(recv[recv.index('450000'):].decode('hex'))
                else:
                    self.current_pack = Ether(recv)#TODO check if arp gets this
            elif recv == 'disect':#already been modded
                pass
            
            # fix chksum and len
            try:
                del (self.current_pack['IP'].chksum)
            except:
                pass
            try:
                del (self.current_pack['TCP'].chksum)
            except:
                pass
            #TODO check chksum.....
            self.clearDisect()
            self.clearRaw()
            #handle updated packet
            if self.pcapfile:
                wrpcap(self.pcapfile, org, append=True)
                wrpcap(self.pcapfile[:-5] + '_mod.pcap', self.current_pack, append=True)
            print 'sending updated....',raw(self.current_pack)
            print 'rather than........',data
            #TODO if eth layer changed, NF_DROP and use scapy to send self.current_pack
            if org['Ether'] != self.current_pack['Ether']:
                if data:
                    self.ether_pass.append(self.current_pack)
                    sendp(self.current_pack)
                    self.display_lock.release()
                    return raw(self.current_pack), interceptor.NF_DROP
                elif self.intercepting:
                    sendp(self.current_pack)
                    return
            button.destroy()
            self.display_lock.release()
            # TODO efficently delte self from packet queue
            if data:
                return raw(self.current_pack['IP']), interceptor.NF_ACCEPT
            elif self.intercepting:
                sendp(self.current_pack)
                return
        else:
            print 'not intercpeting..'
            try:
                button.destroy()
            except:
                pass
            if self.is_outgoing:
                self.tbmg.disecttextS.insert('3.0', self._packet_disect_nointercept(self.current_pack))
                self.tbmg.rawtextS.insert('0.0', '\n- ' + str(raw(self.current_pack)).encode('hex'))
            else:
                self.tbmg.disecttextR.insert('3.0', self._packet_disect_nointercept(self.current_pack))
                self.tbmg.rawtextR.insert('0.0', '\n- ' + str(raw(self.current_pack)).encode('hex'))
            if self.pcapfile:
                wrpcap(self.pcapfile, self.current_pack, append=True)
                wrpcap(self.pcapfile[:-5] + '_mod.pcap', self.current_pack, append=True)
            self.display_lock.release()
            if data:
                return raw(self.current_pack['IP']), interceptor.NF_ACCEPT
            else:
                return
