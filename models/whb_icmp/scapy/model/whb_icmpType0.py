#!/usr/bin/python
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
#  create a whb_icmp Type: 0
from scapy.all import *

class whb_icmpType0(Packet):
    name='whb_icmpType0'
    fields_desc = [
        ByteField("icmp_type_34", 0x00),
        ByteField("icmp_code_35", 0x00),
        XShortField("icmp_checksum_36", 0x77e9),
        XShortField("icmp_ident_38", 0x7725),
        XShortField("icmp_seq_40", 0x0001),
        XLongField("icmp_data_time_42", 0xb94c885500000000),
        StrField("data_data_50", "\x0D\x7B\x03\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37"),
    ]
    #TODO
    #def __init__(self):
    #    self.name = 'whb_icmp1'
    #    self.protocol_id = getattr(IP_PROTOS, 'icmp')

    #TODO
    #def buildPacket(self, s, d):
    #    '''Construct packet to send.'''
        #s = self.strIP('
        ##
        ##')
        #d = self.strIP('
        ##
        ##')
    #    return IP(src=s, dst=d)/whb_icmp1()
      