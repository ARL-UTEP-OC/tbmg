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
        
        self.proxy = Process(target=self._runProxy, args=(self.child_conn,))
        self.proxy.daemon = True
        self.proxythread = threading.Thread(target=self.updateTBMG)
        self.proxythread.daemon = True
        self.proxythread.start()
        self.q = nfqueue.queue()
    
    def updateTBMG(self):
        while 1:
            if self.status and self.parent_conn:
                hexval = self.parent_conn.recv()
                pkt = Raw(hexval)
                ip = IP(pkt)
                #print 'got:'+text
                #self.tbmg.rawtext.delete(1.0, 'END')
                self.tbmg.rawtext.insert('3.0', '\n- '+str(hexval).encode('hex'))
                self._packet_disect_populate(ip)
                #self.tbmg.disecttext.insert('3.0', self._packet_disect(ip))
                
            time.sleep(0.1)
    
    def sendRawUpdate(self):
        text = self.tbmg.rawtext.get('3.2')
        print 'updating to:', text
        self.parent_conn.send(text.decode('hex'))
        
    def sendDisectUpdate(self):
        pass

    def _packet_disect_populate(self, pack):
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
                    entry = Entry(self.tbmg.disectlist.interior)
                    entry.grid(row=rownum, column=2)
                    entry.insert(0,str(l.fields[f]))
                    self.gui_layers[l.name].append((layer,label,entry))
                    rownum+=1
            except Exception, e:
                print e, l
                break

    def _packet_disect_str(self, pack):
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
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
        elif self.drop:
            payload.set_verdict(nfqueue.NF_DROP)
        else:
            payload.set_verdict(nfqueue.NF_ACCEPT)
            
    def setFilter(self, text):
        self.filter = text
    
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
    
     
    

    
    #def main():
    #    # This is the intercept
    #    q = nfqueue.queue()
    #    q.open()
    #    q.bind(socket.AF_INET)
    #    q.set_callback(callback)
    ##    q.create_queue(0)
    #    try:
    #        q.try_run() # Main loop
    #    except KeyboardInterrupt:
    #        q.unbind(socket.AF_INET)
    #        q.close()
    #        print("Flushing iptables.")
    #        # This flushes everything, you might wanna be careful
    #        #may want a way to restore tables after
    #        os.system('iptables -F')
    #        os.system('iptables -X')
    
    
    #if __name__ == "__main__":
    #	main()
