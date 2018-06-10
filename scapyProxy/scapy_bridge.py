"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

#from netfilterqueue import NetfilterQueue
from Tkinter import *
import nfqueue
from scapy.all import *
import os
import threading
from multiprocessing import Process, Pipe
import time
from scapyProxy.GuiUtils import VerticalScrolledFrame
from socket import gaierror


class ScapyBridge(object):
    
    def __init__(self,tbmg_):
        self.iptablesr = "iptables -A OUTPUT -j NFQUEUE"
        self.tbmg = tbmg_
        self.q = None
        self.status = False
        self.filter = None
        self.drop = None
        self.parent_conn, self.child_conn = Pipe()
        self.pcapfile = ''
        self.intercept = False
        self.gui_layers = {} # gui_layers['IP'] = [(Label(text=layer),Label(text=feild_name),Entry(text=feild_value)),(L,E),...]
        self.current_pack=None
        
        self.proxy = Process(target=self._runProxy, args=(self.child_conn,))
        self.proxy.daemon = True
        self.proxythread = threading.Thread(target=self.updateTBMG)
        self.proxythread.daemon = True
        self.proxythread.start()
        self.q = nfqueue.queue()
    
    #ran on thread to get updates from process
    def updateTBMG(self):
        while 1:
            if self.status and self.parent_conn:
                hexval = self.parent_conn.recv()
                pkt = Raw(hexval)
                ip = IP(pkt)
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
    
    def sendRawUpdate(self):
        text = str(self.tbmg.rawtext.get('0.0',END)).strip()
        print 'updating to:', text
        self.parent_conn.send(text.decode('hex'))
        
    def sendDisectUpdate(self):
        print 'current:',self.current_pack
        if not self.gui_layers or len(self.tbmg.disectlist.interior.grid_slaves())<2:
            return
        for layer in self.gui_layers:
            if layer and layer in self.current_pack:
                for pair in self.gui_layers[layer]:
                    value = '0'
                    try:
                        value = str(int(pair[2].get()))
                    except:
                        value = '"'+str(pair[2].get())+'"'
                        try:
                            value = value.encode('utf8')
                        except:
                            value = value.encode('hex')
                    #TODO add protocol exceptions here!
                    if layer == 'TCP' and pair[1].cget('text')=='options':
                        #if str(pair[2].get()):
                        #    self.current_pack['TCP'].options = str(pair[2].get())
                        continue
                    if layer == 'IP' and pair[1].cget('text')=='flags':
                        if value and value is not '""' and str(pair[2].get()):
                            print 'USING:', str(pair[2].get())
                            self.current_pack['IP'].flags = str(pair[2].get())
                        else:
                            self.current_pack['IP'].flags = None
                        continue
                    if layer == 'IP in ICMP' and pair[1].cget('text')=='flags':
                        if value and value is not '""' and str(pair[2].get()):
                            print 'USING:', str(pair[2].get())
                            self.current_pack['IP in ICMP'].flags = str(pair[2].get())
                        else:
                            self.current_pack['IP in ICMP'].flags = None
                        continue
                    if layer == 'DNS' and pair[1].cget('text')=='qd':
                        self.current_pack['DNS'].qd = str(pair[2].get())
                        continue
                    if value == '"None"':
                        value = 'None'
                    # TODO add protocol exceptions here!
                    execute = "self.current_pack['" + layer + "']." + pair[1].cget('text') + " = " + value
                    print('setting:', execute)
                    try:
                        exec(execute)
                    except ValueError,ve:
                        print 'FAILED-ValueErr', ve
                    except gaierror,e:
                        print(self.current_pack)
                        print('GAI ERROR:', e)
        r = raw(self.current_pack)
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
                layer.grid(row=rownum,column=0)
                rownum+=1
                for f in l.fields:
                    label = Label(self.tbmg.disectlist.interior, text=str(f))
                    label.grid(row=rownum,column=1)
                    entry = Entry(self.tbmg.disectlist.interior, width=30)
                    entry.grid(row=rownum, column=2)
                    entry.insert(0,str(l.fields[f]))
                    self.gui_layers[l.name].append((layer,label,entry))
                    rownum+=1
            except Exception, e:
                print e, l
                break
        #self.tbmg.update()

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
            except Exception,e:
                print e, l
                break
        result += "\n*****************************\n"
        return result
    
    def interceptToggle(self):
        self.intercept = not self.intercept
        print 'intercpet is now',self.intercept
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
                self.q.open()
                self.q.bind(socket.AF_INET)
                self.q.set_callback(self.callback)
                #if self.intercept:
                #    self.q.create_queue(1)
                #else:
                self.q.create_queue(0)
                if self.intercept:
                    self.q.set_queue_maxlen(1)
                print (dir(self.q))
                self.proxy.start()
            except Exception,e:
                print e
                a=None
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

    def setFilter(self, text):
        self.filter = text

    #ran from seperate process
    def callback(self, number, payload=None): # the4960- added 'number' param
        # Here is where the magic happens.
        data = payload.get_data()
        pkt = IP(data)
        print("Got a packet:", str(pkt.src), str(pkt.dst))
        if self.pcapfile:
            wrpcap(self.pcapfile, pkt, append=True)
        if self.filter:
            if eval(self.filter):
                #TODO
                a=1
        self.child_conn.send(raw(pkt))
        if self.intercept:
            new_ptk = IP(self.child_conn.recv())
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(new_ptk), len(new_ptk))
        elif self.drop:
            payload.set_verdict(nfqueue.NF_DROP)
        else:
            payload.set_verdict(nfqueue.NF_ACCEPT)
            
    #ran as a process
    def _runProxy(self, child_conn):
        try:
            self.child_conn = child_conn
            self.q.try_run()  # Main loop
        except KeyboardInterrupt:
            self.q.unbind(socket.AF_INET)
            self.q.close()
            print("Flushing iptables.")
            # This flushes everything, you might wanna be careful
            # may want a way to restore tables after
            os.system('iptables -F')
            os.system('iptables -X')