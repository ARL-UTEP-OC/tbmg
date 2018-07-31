import sys
sys.path.insert(0, '/root/tbmg/scapyProxy/')
from HookUtils import *
from scapy.all import *

class SecondaryGoogle(PacketHook):
    def run(self):
        try:
            self.scapy_packet['ICMP']
            if self.scapy_packet['IP'].dst == '8.8.8.8' :
                print 'found 8.8.8.8'
                self.scapy_packet['IP'].dst = '8.8.4.4'
        except Exception as e:
            print 'err:',e
        return self.accept()

if __name__=='__main__':
    pack = IP(dst='8.8.8.8')/ICMP()
    pack.show()
    hook = SecondaryGoogle(pack)
    newpack,a_or_r = hook.run()
    newpack.show()
