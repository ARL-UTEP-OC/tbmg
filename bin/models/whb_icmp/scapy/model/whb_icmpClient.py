from scapy.all import *
from grammar import whb_icmpGrammar
from whb_icmpType0 import whb_icmp0
from whb_icmpType1 import whb_icmp1

class whb_icmpClient():

    def __init__(self, src, dst):
        self.grammar = whb_icmpGrammar.whb_icmpStateMachine(0)
        self.name = 'whb_icmp'
        self.protocol_id = getattr(IP_PROTOS, 'icmp')
        self.src = src
        self.dst = dst

        self.types = []
        self.types.append(whb_icmp0())
        self.types.append(whb_icmp1())

    def bind(self):
        '''Bind new layer for dissecting.
        Binding only needs to occur once as each type shares the same fields.'''
        split_layers(IP, ICMP, proto=self.protocol_id)
        bind_layers(IP, whb_icmp1, proto=self.protocol_id)
        
    def sniffFilter(self, packet):
        if packet.haslayer(whb_icmp1) and packet[IP].src==self.dst:
            print "Valid packet recieved:",packet.show()
            return 1
        return 0
        
    def getLayers(self, pkt):
        yield pkt.name
        while pkt.payload:
            pkt = pkt.payload
            yield pkt.name
    
    def reply(self, packet):
        '''Build response based on the grammar.'''
        t = packet[whb_icmp1].icmp_type_34
        print "Received type: " + str(t)
        #TODO convert the packet type into the state machine's number
        t=0
        
        nextState = self.grammar.getNextState(t)
        print "Next state: " + str(nextState)
        
        #TODO test the back and forth
        exit()
        
        #send(getPacket('127.0.0.1'))
        
    def start(self):
        '''Start communicating.'''
        self.bind()
        sniff(lfilter=self.sniffFilter, prn=self.reply)