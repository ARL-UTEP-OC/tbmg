#!/usr/bin/python
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
#  create a protoxtest Type: 48
from scapy.all import *

class sampleLenField(Packet):
    name='sampleLenField'
    fields_desc = [
        XIntField("sample_preamble_66", 0xffffff81),
        XIntField("sample_msgid_70", 0x00000030),
        FieldLenField("sample_msglen_74", None, fmt="I", length_of="sample_data_82"),
        XIntField("sample_msgnum_78", 0x00000000),
        StrLenField("sample_data_82", '\x00\x00\x00\x00', length_from=lambda x: x.sample_msglen_74),
    ]
