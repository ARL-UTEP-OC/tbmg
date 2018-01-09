#!/usr/bin/python
#Creates a file containing packet type sequences from an input field data file
import sys
from lxml import etree
from bs4 import BeautifulSoup

if len(sys.argv) != 3:
	print "usage: packetTypeExtractory.py <input file> <model name>"
	print "<input file>"
	print " -a file containing field data (produced by pdmlExtractor.py)\n"
	print "<model name>"
	print " -a file containing field data (produced by pdmlExtractor.py)\n"
	print "This program creates two files: "
	print "packetTypeSequences.txt"
	print " -this file contains the observed packet type sequences in the input file"
	print "packetTypeMapping.xml"
	print " -this file contains the mappings from numerical packet types to the unique values used as identify a unique packet type"
	sys.exit(-1) 
inputFile = sys.argv[1]
modelName = sys.argv[2]
outputFilename = 'packetTypeSequences.txt'

TYPE_IDENTIFIERS = ["Type", "type", "Message Type", "message type", "Command", "command", "GET", "POST", "NOTIFY"]
TYPE_FIELDS = ["macsrc","macdst","ipsrc","ipdst","protoName"]
FIELD_FIELDS = ["mname", "mshowname", "msize", "mpos", "mshow", "mvocab", "mentropy"]

typeMappings = {}
typeSequences = []
#---------------process the input file------------------#
soup = BeautifulSoup(open(inputFile,'r'), 'lxml')
#iterate through each packet:
for packetXML in soup.find_all('packet'):
	#iterate through each field in the packet
	for fieldXML in packetXML.find_all('field'):
		#check if the current field is a type specifier
		#print fieldXML.mshowname.contents[0].split(':')[0]
		if fieldXML.mshowname.contents[0].split(':')[0] in TYPE_IDENTIFIERS:
			dataItem = (packetXML['macsrc'],packetXML['macdst'],
			packetXML['ipsrc'],packetXML['ipdst'],
			fieldXML.mshowname.contents[0])
			#store in type mappings if it is not there yet:
			if dataItem not in typeMappings:
				#give this new item an identifier (current number of elements in the array)
				typeMappings[dataItem] = len(typeMappings) 
			typeSequences.append(typeMappings[dataItem])
#-------------output section------------------------#
#print an error statement if no types were found:
if len(typeMappings) == 0:
	print "No types found in input file!"
	exit

#write to the output file and to stdout
out = open(outputFilename, 'w')
for i in typeSequences:
	sys.stdout.write(str(i)+" ")
	out.write(str(i) + " ")
sys.stdout.write("\n")
out.write("\n")
out.close()

#create the xml tree:
typeMappingsXML = etree.Element("mapping_list")
for mapping in typeMappings:
	mappingElement = etree.SubElement(typeMappingsXML,"mtype", id=str(typeMappings[mapping]))
	#add each of the items that were used to create the key tuples
	for i in range(len(TYPE_FIELDS)):
		mappingElement.set(TYPE_FIELDS[i],mapping[i])

outputMappingXML = open('packetTypeMapping.xml','w')
print etree.tostring(typeMappingsXML,pretty_print='true')
outputMappingXML.write(etree.tostring(typeMappingsXML,pretty_print='true'))
