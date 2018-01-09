#!/usr/bin/python
#Creates a C++ NS-3 WScript file

from bs4 import BeautifulSoup
from jinja2 import Template
import sys

xmlFilename = sys.argv[1]
modelName = sys.argv[2]

soup = BeautifulSoup(open(xmlFilename,'r'), 'xml')

def generateFile(filename, mids):
	wscriptFile = Template('''
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

# def options(opt):
#     pass

# def configure(conf):
#     conf.check_nonfatal(header_name='stdint.h', define_name='HAVE_STDINT_H')

def build(bld):
    module = bld.create_ns3_module('{{jinjaModelName}}', ['core'])
    module.source = [
        'model/{{jinjaModelName}}.cc',
        {%- for type in jinjaPacketTypes %}
        'model/{{jinjaModelName}}-type{{type}}.cc',
        {%- endfor %}
        'helper/{{jinjaModelName}}-helper.cc',
        'model/{{jinjaModelName}}-PacketFactory.cc',
        'model/{{jinjaModelName}}-PacketType.cc',
        ]

    module_test = bld.create_ns3_module_test_library('{{jinjaModelName}}')
    module_test.source = [
        'test/{{jinjaModelName}}-test-suite.cc',
        ]

    headers = bld(features='ns3header')
    headers.module = '{{jinjaModelName}}'
    headers.source = [
        'model/{{jinjaModelName}}.h',
        {%- for type in jinjaPacketTypes %}
        'model/{{jinjaModelName}}-type{{type}}.h',
        {%- endfor %}
        'model/{{jinjaModelName}}Grammar.h',
        'helper/{{jinjaModelName}}-helper.h',
        'model/{{jinjaModelName}}-PacketFactory.h',
        'model/{{jinjaModelName}}-PacketType.h',
        ]

    if bld.env.ENABLE_EXAMPLES:
        bld.recurse('examples')
    # bld.ns3_python_bindings()
''')
	ofile = open(filename, 'w')
	ofile.write(wscriptFile.render(jinjaPacketTypes=mids, jinjaModelName=modelName, todo='TODO'))
	#print wscriptFile.render(jinjaPacketTypes=mids, jinjaModelName=modelName, todo='TODO')

def calcStrOr(smaller, smallerNumBytes, larger, largerNumBytes):
	numBytesDiff = largerNumBytes-smallerNumBytes
	largerBase16 = int(larger,16)
	smallerBase16 = int(smaller,16) << (8*numBytesDiff)
	 
	return (hex(largerBase16 | smallerBase16))[2:]

def main():
	ids = soup.find_all('mtype',{'id':True})
	outputPath = modelName+"/"+modelName+"model/"
	answer = []
	for mid in ids:
		answer.append(mid['id'])
	generateFile(outputPath+"wscript",answer)

if __name__ == "__main__":
	main()
