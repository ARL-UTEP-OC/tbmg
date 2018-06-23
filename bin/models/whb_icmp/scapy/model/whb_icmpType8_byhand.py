#!/usr/bin/python
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
#  create a whb_icmp Type: 8
from scapy.all import *

# **TBMG_PRE... WARNING: DO NOT MANUALLY EDIT CODE INSIDE TAG
import struct,time,inspect
from collections import OrderedDict
# ***_GENERAL_...
import random
# ..._GENERAL_***
# ..TBMG_PRE*** WARNING: DO NOT MANUALLY EDIT CODE INSIDE TAG
class whb_icmpType8(Packet):
    name='whb_icmpType8'
    fields_desc = [
        ByteField("icmp_type_34", 0x08),
        ByteField("icmp_code_35", 0x00),
        XShortField("icmp_checksum_36", 0x6fe9),
        XShortField("icmp_ident_38", 0x7725),
        XShortField("icmp_seq_40", 0x0001),
        XLongField("icmp_data_time_42", 0xb94c885500000000),
        StrField("data_data_50", "\x0D\x7B\x03\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37"),
    ]
    #TODO
    #def __init__(self):
    #    self.name = 'whb_icmp0'
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
    #    return IP(src=s, dst=d)/whb_icmp0()
      
# **TBMG... WARNING: DO NOT MANUALLY EDIT CODE INSIDE TAG
    __slots__ = ["synthfields"]
    def post_build(self, packet_bytes, payload_bytes):
        initsynth = False
        for i in inspect.getmembers(self):
            if i[0] == 'synthfields':
                initsynth = True
        if not initsynth:
            self.synthfields = OrderedDict()
        lastsynthfields = self.synthfields
        synthfields = OrderedDict()
        synthfields["__class"] = 'whb_icmpType8'
# **_FIELDS_...

# ***icmp_type_34...
# NONE
        synthfields['icmp_type_34'] = packet_bytes[(34-34):(35-34)]
# ...icmp_type_34***

# ***icmp_code_35...
# CUSTOM
        field_start = 35-34
        field_end = 36-34
        field_bytes = packet_bytes[field_start:field_end]
# ****code...
        field_bytes = struct.pack("!B",random.randint(64,128))
# ....code***
        synthfields['icmp_code_35'] = field_bytes
        packet_bytes = packet_bytes[0:field_start]+field_bytes+packet_bytes[field_end:]
# ...icmp_code_35***

# ***icmp_checksum_36...
# CHKSUM INET REST !
        if self.icmp_checksum_36 is None:
            chk = checksum(packet_bytes[(38-34):]+payload_bytes)
            packet_bytes = packet_bytes[0:(36-34)]+struct.pack("!H", chk)+packet_bytes[(38-34):]
        synthfields['icmp_checksum_36'] = packet_bytes[(36-34):(38-34)]
# ...icmp_checksum_36***

# ***icmp_ident_38...
# LEN data_data_50 !
        if self.icmp_ident_38 is None:
            length = len(self.data_data_50)
            packet_bytes = packet_bytes[0:(38-34)]+struct.pack("!H",length)+packet_bytes[(40-34):]
        synthfields['icmp_ident_38'] = packet_bytes[(38-34):(40-34)]
# ...icmp_ident_38***

# ***icmp_seq_40...
# SEQ 1 1 !
        if self.icmp_seq_40 is None:
            seq = (lastsynthfields['icmp_seq_40'] if 'icmp_seq_40' in lastsynthfields else 0)
            seq += 1/1
            packet_bytes = packet_bytes[0:(40-34)]+struct.pack("!H",seq)+packet_bytes[(42-34):]
        synthfields['icmp_seq_40'] = packet_bytes[(40-34):(42-34)]
# ...icmp_seq_40***

# ***icmp_data_time_42...
# TIMESTAMP 0 <
        if self.icmp_data_time_42 is None:
            ts = time.time() + 0
            packet_bytes = packet_bytes[0:(42-34)]+struct.pack("!Q",ts)+packet_bytes[(50-34):]
        synthfields['icmp_data_time_42'] = packet_bytes[(42-34):(50-34)]
# ...icmp_data_time_42***

# ***data_data_50...
# CUSTOM
        field_start = 50-34
        field_end = len(packet_bytes)
        field_bytes = packet_bytes[field_start:field_end]
# ****code...
        hax = "TESTING"
        if len(field_bytes) > len(hax):
            field_bytes = struct.pack("!"+str(len(hax))+"s",hax)+field_bytes[len(hax):]
# ....code***
        synthfields['data_data_50'] = field_bytes
        packet_bytes = packet_bytes[0:field_start]+field_bytes+packet_bytes[field_end:]
# ...data_data_50***

# .._FIELDS_***

# **_GENERAL_...
        print "Custom code running..."
        print "total packet length: "+str(len(packet_bytes))
        synthfields['invisible'] = 'testing'
# .._GENERAL_***

        print "###[ whb_icmpType8 ]###"
        for f in synthfields:
            print "      "+f.rjust(20)+" = "+repr(synthfields[f])

        self.synthfields = synthfields
        return packet_bytes+payload_bytes
# ..TBMG*** WARNING: DO NOT MANUALLY EDIT CODE INSIDE TAG
