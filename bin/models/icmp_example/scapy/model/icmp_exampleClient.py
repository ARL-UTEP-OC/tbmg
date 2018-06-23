from scapy.all import *
from grammar import icmp_exampleGrammar
from icmp_exampleType0 import icmp_example0
from icmp_exampleType1 import icmp_example1

class icmp_exampleClient():

    def __init__(self, src, dst):
        self.grammar = icmp_exampleGrammar.icmp_exampleStateMachine(0)
        self.name = 'icmp_example'
        self.protocol_id = getattr(IP_PROTOS, 'icmp')
        self.src = src
        self.dst = dst

        self.types = []
        self.types.append(icmp_example0())
        self.types.append(icmp_example1())

    def bind(self):
        '''Bind new layer for dissecting.
        Binding only needs to occur once as each type shares the same fields.'''
        split_layers(IP, ICMP, proto=self.protocol_id)
        bind_layers(IP, icmp_example1, proto=self.protocol_id)
        
    def sniffFilter(self, packet):
        if packet.haslayer(icmp_example1) and packet[IP].src==self.dst:
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
        t = packet[icmp_example1].icmp_type_34
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