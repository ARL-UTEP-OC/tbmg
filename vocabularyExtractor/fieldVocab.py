#!/usr/bin/python
# Creates a file containing packet type sequences from an input field data file
import sys
from lxml import etree
from bs4 import BeautifulSoup
from collections import OrderedDict
import operator
import os

def extractVocab(modelName):
    inputPacketsTypesFile = os.path.join("models",modelName,"packetsTypes.xml")
    outputFilename = os.path.join("models",modelName,'modelStandardizedXMLFile.xml')

    packetTypeAppearances = 0
    # we want to keep track of fields in order
    fields = OrderedDict()

    # Create the root element for the output file:
    modelXML = etree.Element(modelName)

    # ---------------process the input file------------------#
    soup = BeautifulSoup(open(inputPacketsTypesFile, 'r'), 'xml')
    # get all of the unique packet types:
    setPacketTypes = set()
    for packetType in soup.find_all('packet'):
        try:
            setPacketTypes.add(packetType['type'])
        except:
            continue
            	
    # for each unique packet type
    for packetType in setPacketTypes:
        # iterate through each packet per type:
        fields.clear()
        packetTypeAppearances = 0
        for packetXML in soup.find_all('packet', type=packetType):
            packetTypeAppearances = packetTypeAppearances + 1
            # iterate through each field in the packet
            for fieldXML in packetXML.find_all('field'):
                # store the unique values in all fields
                # The resulting structure is as follows:
                # field dictionary contains fieldnames dictionary
                #  fieldnames dictionary contains fieldvalues list
                # an example reference is the following:
                # fields['icmp.code']['size']
                # this will print out a list of all of the values in the size field
                for child in fieldXML.find_all(True, recursive=False):
                    # print "CHILD_contents[0]",child.contents[0],"MNAME[0]",fieldXML.mname.contents[0]
                    if fieldXML.mname.contents:
                        if fieldXML.mname.contents[0].strip() not in fields:
                            #	print fieldXML.mname.contents[0].strip()
                            fields[fieldXML.mname.contents[0].strip()] = {}
                        if child.name not in fields[fieldXML.mname.contents[0].strip()]:
                            #	print child.name
                            fields[fieldXML.mname.contents[0].strip()][child.name] = []
                        try:
                            if child.contents[0].strip() not in fields[fieldXML.mname.contents[0].strip()][child.name]:
                                fields[fieldXML.mname.contents[0].strip()][child.name].append(child.contents[0].strip())
                        except:
                            continue
                    else:
                        {}  # strange case when field has no name
        # -----------process the field entropy and mvocab-------#
        # create the types element and include all of the attributes that make it a unique type:
        typeXML = etree.SubElement(modelXML, "mtype", id=packetXML['type'],
                                   nodeuniq=packetXML['nodeuniq'],
                                   typeuniq=packetXML['typeuniq'])
        # add all of the subelements that belong to this packet type
        for fieldName in fields:
            fieldXML = etree.SubElement(typeXML, "mfield")
            for metaFieldname in fields[fieldName]:
                metaFieldXML = etree.SubElement(fieldXML, metaFieldname)
                metaFieldXML.text = ""
                for vocabItem in fields[fieldName][metaFieldname]:
                    metaFieldXML.text = str(metaFieldXML.text) + str(vocabItem) + ";"
            # THIS IS WHERE I COULD CALCULATE OTHER stats for the fields
            # calculate the 'value' vocabulary entropy
            numberOfDifferentValues = len(fields[fieldName]['mvalue']) if 'mvalue' in fields[fieldName] and len(
                fields[fieldName]['mvalue']) != 1 else 0
            etree.SubElement(fieldXML, "mentropy").text = str(numberOfDifferentValues / (packetTypeAppearances * 1.0))
        # add an attribute containing the number of times this packet type was observed
        typeXML.set('appears', str(packetTypeAppearances))

    # Sort the fields in the output file

    # for container in modelXML.findall('mtype'):
    #	data = []
    #
    #	for elem in container:
    #		mpos = elem.findtext("mpos")
    #		mpos = int(mpos.split(';')[0])
    #
    #		msize = elem.findtext("msize")
    #		msize = int(msize.split(';')[0])
    #
    #		data.append((mpos, msize, elem))
    #	data.sort(reverse=True, key=operator.itemgetter(1))
    #	data.sort(reverse=False, key=operator.itemgetter(0))
    #	container[:] = [item[-1] for item in data]

    for container in modelXML.findall('mtype'):
        data = []
        for elem in container:
            if elem.findtext("mpos"):
                mpos = int(elem.findtext("mpos").split(';')[0])
                data.append((mpos, elem))
        data.sort(reverse=False, key=operator.itemgetter(0))
        container[:] = [item[-1] for item in data]

    out = open(outputFilename, 'w')
    out.write(etree.tostring(modelXML, pretty_print='true'))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "usage: fieldVocab.py <input file> <model name>"
        print "<input file>"
        print " -a file containing a packet trace containing packet type attributes\n"
        print "<model name>"
        print " -the name of the model that is being generated\n"
        print "This program creates one file: "
        print "modelStandardizedXMLFile.xml"
        print " -this file contains field vocabularies for each packet type"
        sys.exit(-1)
    extractVocab(sys.argv[1])
