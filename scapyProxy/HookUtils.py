import interceptor
from scapy.all import *


class AbstractHook(object):
    def __init__(self,scapy_packet_,description_=None):
        self.scapy_packet = scapy_packet_
        self.description = description_
    def run(self):
        pass
    
    
class FilterHook(AbstractHook):
    def __init__(self, scapy_packet_, description_=None):
        super(AbstractHook, self).__init__(scapy_packet_,description_=None)
        self.interfaces = []
    
    def catch(self):
        return True
    
    def ignore(self):
        return False
    
    def run(self):
        pass


class PacketHook(AbstractHook):
    def __init__(self, scapy_packet_, description_=None):
        super(AbstractHook, self).__init__(scapy_packet_,description_=None)
        self.filter_bnf = ''
        self.filter_hook =['','']
    
    def accept(self):
        return IP(raw(self.scapy_packet).decode('hex')), interceptor.NF_ACCEPT
    
    def drop(self):
        return IP(raw(self.scapy_packet).decode('hex')), interceptor.NF_DROP
    
    def mod(self):
        return IP(raw(self.scapy_packet).decode('hex')), interceptor.NF_ACCEPT
    
    def run(self):
        pass