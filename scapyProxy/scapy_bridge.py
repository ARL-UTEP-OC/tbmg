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
        
        self.proxy = Process(target=self._runProxy, args=(self.child_conn,))
        self.proxy.daemon = True
        self.proxythread = threading.Thread(target=self.updateTBMG)
        self.proxythread.daemon = True
        self.proxythread.start()
        self.q = nfqueue.queue()
    
    def updateTBMG(self):
        while 1:
            if self.status and self.parent_conn:
                text = str(self.parent_conn.recv()).encode('hex')
                print 'got:'+text
                #self.tbmg.rawtext.delete(1.0, 'END')
                self.tbmg.rawtext.insert('3.0', '\n'+text+'....')
                #self.tbmg.rawtext.configure(text=text)
            time.sleep(0.25)
                
        
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
                self.q.create_queue(0)
                self.proxy.start()
            except:
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
        if self.intercept:
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))
        elif self.drop:
            payload.set_verdict(nfqueue.NF_DROP)
        else:
            payload.set_verdict(nfqueue.NF_ACCEPT)
            self.child_conn.send(str(data))
            
        
    
    def filterProxy(self, text):
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
