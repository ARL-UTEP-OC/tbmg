"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

# from netfilterqueue import NetfilterQueue
from Tkinter import *
from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import threading
from multiprocessing import Process, Pipe
import time
from scapyProxy.GuiUtils import VerticalScrolledFrame
from socket import gaierror
import chardet
import socket


class ScapyBridge(object):
    
    def __init__(self, tbmg_):
        # output catches outgoing packets, input from other machines, and forward for mitm
        self.iptablesr = "iptables -A OUTPUT -j NFQUEUE --queue-num 2; iptables -A FORWARD -j NFQUEUE --queue-num 2; iptables -A INPUT -j NFQUEUE --queue-num 2"
        #self.iptablesr = ""#""iptables -t nat -A PREROUTING -j NFQUEUE --queue-num 2"
        self.tbmg = tbmg_
        self.q = None
        self.status = False
        self.filter = None
        self.parent_conn, self.child_conn = Pipe()
        self.pcapfile = ''
        self.intercept = False
        self.gui_layers = {}  # gui_layers['IP'] = [(Label(text=layer),Label(text=feild_name),Entry(text=feild_value)),(L,E),...]
        self.current_pack = None
        self.sock = None

        self.q = NetfilterQueue()
        self.proxy = Thread(target=self.q.run_socket, args=(self.sock,))#, args=(block=False))
        self.proxy.setDaemon(True)
        self.proxythread = threading.Thread(target=self.updateTBMG)
        self.proxythread.daemon = True
        self.proxythread.start()
        

    # ran on thread to get updates from process
    def updateTBMG(self):
        while 1:
            if self.status and self.parent_conn:
                hexval = self.parent_conn.recv()
                pkt = Raw(hexval)
                arp = ARP(hexval)
                del (arp['Padding'])
                ip = arp / IP(pkt)
                try:
                    del (ip['Padding'])
                except:
                    pass
                print 'gui got:', ip.summary()
                if self.intercept:
                    self.current_pack = ip
                    self.clearDisect()
                    self.clearRaw()
                    self._packet_disect_intercept(ip)
                    self.tbmg.rawtext.insert('0.0', str(hexval).encode('hex'))
                else:
                    self.tbmg.disecttext.insert('3.0', self._packet_disect_nointercept(ip))
                    self.tbmg.rawtext.insert('0.0', '\n- ' + str(hexval).encode('hex'))
            time.sleep(0.1)
    
    def sendDrop(self):
        self.parent_conn.send('drop')
    
    def sendRawUpdate(self):
        text = str(self.tbmg.rawtext.get('0.0', END)).strip()
        print 'updating to:', text
        self.parent_conn.send(text.decode('hex'))
    
    def sendDisectUpdate(self):
        print 'current:', str(raw(self.current_pack)).encode('hex')
        if not self.gui_layers or len(self.tbmg.disectlist.interior.grid_slaves()) < 2:
            return
        for layer in self.gui_layers:
            if layer and layer in self.current_pack:
                for pair in self.gui_layers[layer]:
                    type1 = None  # correct type for feild
                    exec ("type1 = type (self.current_pack['" + layer + "']." + pair[1].cget('text') + ")")
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
                    if type(value) == str and len(value) >= 4 and value[1] == '[' and value[
                        -2] == ']' and type1 == type([]):
                        print 'found array type', value
                        value = value[1:-1]
                    if value == '"None"':
                        if type1 == type(None):
                            continue
                        if type1 == int:
                            value = '0'
                        else:
                            value = 'None'
                    if value == '""':
                        value = 'None'
                    if layer == 'Raw' and pair[1].cget('text') == 'load':  # ping 8.8.4.4
                        equal = self.current_pack[layer].load == value[1:-1]
                        if not equal:
                            print("FOUND CHANGE in RAW!!!", value, value.encode('hex'))
                            print(self.current_pack['Raw'].load, self.current_pack['Raw'].load.encode('hex'))
                            print('------------------')
                            continue  # use default val
                        self.current_pack['Raw'].load = value[1:-1]
                        continue
                    # TODO add protocol exceptions here!
                    change = False
                    
                    equalstr = "self.current_pack['" + layer + "']." + pair[1].cget('text') + " == " + value
                    print ('checking if equal:', equalstr)
                    equal = eval(equalstr)
                    if not equal:
                        print("FOUND CHANGE!!!", value)
                        print("self.current_pack['" + layer + "']." + pair[1].cget('text') + " == " + value + ")")
                        exec ("print self.current_pack['" + layer + "']." + pair[1].cget('text'))
                        exec ("type2 = type (" + value + ")")
                        print('was:', type1, 'is:', type2)
                        print('------------------')
                    
                    execute = "self.current_pack['" + layer + "']." + pair[1].cget('text') + " = " + value
                    print('setting:', execute)
                    try:
                        exec (execute)
                        exec ("type2 = type (self.current_pack['" + layer + "']." + pair[1].cget('text') + ")")
                        if type1 != type2:
                            print 'ERRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR???', type1, type2
                    except ValueError, ve:
                        print 'FAILED-ValueErr', ve
                    except gaierror, e:
                        print(self.current_pack)
                        print('GAI ERROR:', e)
        r = raw(self.current_pack)
        print('producing from disect:', r.encode('hex'))
        self.parent_conn.send(r)
        self.gui_layers = None
        self.clearDisect()
        self.clearRaw()
    
    def clearDisect(self):
        for w in self.tbmg.disectlist.interior.grid_slaves():
            w.destroy()
    
    def clearRaw(self):
        self.tbmg.rawtext.delete(1.0, END)
    
    def _packet_disect_intercept(self, pack):
        self.clearDisect()
        self.gui_layers = {}
        rownum = 1
        for i in range(10):
            try:
                l = pack.getlayer(i)
                if not l:
                    continue
                self.gui_layers[l.name] = []
                layer = Label(self.tbmg.disectlist.interior, text=l.name)
                layer.grid(row=rownum, column=0)
                rownum += 1
                for f in l.fields:
                    label = Label(self.tbmg.disectlist.interior, text=str(f))
                    label.grid(row=rownum, column=1)
                    entry = Entry(self.tbmg.disectlist.interior, width=30)
                    entry.grid(row=rownum, column=2)
                    try:
                        entry.insert(0, str(l.fields[f]).encode('utf8'))
                    except:
                        print('FOUND ODD ENCODING:', chardet.detect(str(l.fields[f])))
                        entry.insert(0, str(l.fields[f]).encode('hex'))
                    self.gui_layers[l.name].append((layer, label, entry))
                    rownum += 1
            except Exception, e:
                print e, l
                break
        # self.tbmg.update()
    
    def _packet_disect_nointercept(self, pack):
        result = ""
        l = None
        for i in range(10):
            try:
                l = pack.getlayer(i)
                if not l:
                    continue
                result += l.name + "\n----\n"
                for f in l.fields:
                    result += str(f) + " -> " + str(l.fields[f]) + "\n"
                result += "~~~~~~~~~~~~~~~~~~~\n"
            except Exception, e:
                print e, l
                break
        result += "\n*****************************\n"
        return result
    
    def interceptToggle(self):
        self.intercept = not self.intercept
        print 'intercpet is now', self.intercept
        
        def addnointercptGUI():
            self.tbmg.disecttext = Text(self.tbmg.page5, height=50, width=55)
            self.tbmg.disecttextscroll = Scrollbar(self.tbmg.page5)
            self.tbmg.disecttextscroll.config(command=self.tbmg.disecttext.yview)
            self.tbmg.disecttext.config(yscrollcommand=self.tbmg.disecttextscroll.set)
            self.tbmg.disecttext.grid(row=3, column=2)
            self.tbmg.disecttextscroll.grid(row=3, column=3)
            self.tbmg.disecttext.insert(END, 'DISECT\n---\n')
        
        def addintercptGUI():
            self.tbmg.disectlist = VerticalScrolledFrame(self.tbmg.page5, height=100, width=50)
            self.tbmg.disectlist.grid(row=3, column=2)
            self.tbmg.disectLable = Label(self.tbmg.disectlist.interior, text='DISECT VIEW\n----\n')
            self.tbmg.disectLable.grid(row=0, column=0)
        
        if self.intercept:
            if self.tbmg.disecttext or self.tbmg.disecttextscroll:
                self.tbmg.disecttext.destroy()
                self.tbmg.disecttext = None
                self.tbmg.disecttextscroll.destroy()
                self.tbmg.disecttextscroll = None
            if self.tbmg.disectlist and self.tbmg.disectLable:
                pass
            else:
                addintercptGUI()
        else:
            if self.tbmg.disectlist or self.tbmg.disectLable:
                self.tbmg.disectlist.destroy()
                self.tbmg.disectlist = None
                self.tbmg.disectLable.destroy()
                self.tbmg.disectLable = None
            if self.tbmg.disecttext and self.tbmg.disecttextscroll:
                pass
            else:
                addnointercptGUI()
    
    def proxyToggle(self):
        print(not self.status)
        status = not self.status
        if status:
            try:
                print("Adding iptable rules :")
                print(self.iptablesr)
                os.system(self.iptablesr)
                #self.q.open()
                #self.q.bind(socket.AF_INET)
                #self.q.set_callback(self.callback)
                # if self.intercept:
                #    self.q.create_queue(1)
                # else:
                #self.q.create_queue(0)
                #if self.intercept:
                #    self.q.set_queue_maxlen(1)
                #print (dir(self.q))
                #self.proxy.start()
                self.q.bind(2, self.callback)
                self.sock = socket.fromfd(self.q.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.setblocking(True)
                try:
                    # self.child_conn = child_conn
                    print 'about to start proxy'
                    #self.q.run()
                    #self.proxy.start()  # Main loop
                    self.q.run_socket(self.sock)
                    print ('moving after proxy start')
                except KeyboardInterrupt:
                    # self.q.unbind(socket.AF_INET)
                    self.q.unbind()
                    print("Flushing iptables.")
                    # This flushes everything, you might wanna be careful
                    # may want a way to restore tables after
                    os.system('iptables -F')
                    os.system('iptables -X')
            except Exception, e:
                print e
                a = None
        else:
            try:
                self.proxy.join(1)
                print('flushing...')
                os.system('iptables -F')
                os.system('iptables -X')
                self.q.unbind(socket.AF_INET)
                self.q.close()
            except:
                pass
        self.status = status

    # ran from seperate process
    def callback(self, pkt):  # the4960- added 'number' param
        # Here is where the magic happens.
        print 'CALLBACK:', dir(pkt)
        print 'len:', pkt.get_payload_len()
        print 'sock:',(self.sock.recv(4096).encode('hex'))#pkt.get_payload_len()+88
        hw = pkt.get_hw()
        payload = pkt.get_payload()
        mark = pkt.get_mark()
        #print 'hw',hw
        #print 'payload',payload
        #print 'mark',mark
        
        #print 'ip'
        pack = IP(payload)
        print 'scapy',(raw(payload).encode('hex'))
        pack.show()
        pkt.accept()
        #print 'eth'
        #eth = Ether(hw)
        #eth.show()
        #print dir(hw)
        #print dir(payload)
        #print dir(mark)
        
        #data = payload.get_data()
        #eth = Ether(data)
        # del(arp['Padding'])
        #print 'eth:',
        #eth.show()
        '''
        eth = None
        pkt = IP(data)
        
        print("Got a packet:", str(pkt.src), str(pkt.dst))
        dofilter = False  # show package = True
        if self.filter:
            try:
                dofilter = bool(sniff(offline=pkt, filter=self.filter))
                if dofilter:
                    self.child_conn.send(raw(pkt))
            except Exception, e:
                dofilter = False
                print 'Filter err:', self.filter, e
        else:
            self.child_conn.send(raw(pkt))
        pkt = eth / pkt
        try:
            del (pkt['Padding'])
        except:
            pass
        print 'using filter?', dofilter, type(dofilter)
        
        if self.intercept:
            print 'intercepting'
            if dofilter:
                pass
            else:
                print 'intercept, but not in filter'
                payload.set_verdict(nfqueue.NF_ACCEPT)
                if self.pcapfile:
                    wrpcap(self.pcapfile, pkt, append=True)
                    wrpcap(self.pcapfile[:-5] + '_mod.pcap', pkt, append=True)
                return
            recv = self.child_conn.recv()
            if recv == 'drop':
                payload.set_verdict(nfqueue.NF_DROP)
                return
            arp = ARP(recv)
            try:
                del (arp['Padding'])
            except:
                print 'drop?:' + recv
            new_ptk = arp / IP(recv)
            try:
                del (new_ptk['Padding'])
            except:
                pass
            print 'Changed:', pkt.summary()
            print 'To:', new_ptk.summary()
            if self.pcapfile:
                wrpcap(self.pcapfile, pkt, append=True)
                wrpcap(self.pcapfile[:-5] + '_mod.pcap', new_ptk, append=True)
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(new_ptk), len(new_ptk))
        else:
            payload.set_verdict(nfqueue.NF_ACCEPT)
            if self.pcapfile:
                wrpcap(self.pcapfile, pkt, append=True)
                wrpcap(self.pcapfile[:-5] + '_mod.pcap', pkt, append=True)
        '''
    # ran as a process
    #def _runProxy(self):
    