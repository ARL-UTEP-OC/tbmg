#!/usr/bin/python
# Creates a file containing packet type sequences from an input field data file
import sys
from bs4 import BeautifulSoup
import os

def extractPacketType(modelName, keyword):
    inputFile = os.path.join("models",modelName,"packets.xml")

    outputSequenceFilename = os.path.join("models",modelName,'packetTypeSequences.txt')
    outputPacketsTypesFilename = os.path.join("models",modelName,'packetsTypes.xml')
    if keyword != None:
        TYPE_IDENTIFIERS = [ keyword ]
        print "KEYWORD WAS SPECIFIED AS: ",TYPE_IDENTIFIERS
    else:
        TYPE_IDENTIFIERS = ["Flags", "Type", "type", "Message Type", "message type", "Command", "command", "GET", "POST",
                            "NOTIFY", "Message"]
    #
    # TODO: change into the following format: TYPE_IDENTIFIERS[http.request.method] = "Request Method: GET"

    print TYPE_IDENTIFIERS
    # TYPE_FIELDS = ["macsrc","macdst","ipsrc","ipdst","protoName"]
    # FIELD_FIELDS = ["mname", "mshowname", "msize", "mpos", "mshow", "mvocab", "mentropy"]

    typeMappings = {}
    typeSequences = []
    # ---------------process the input file------------------#
    soup = BeautifulSoup(open(inputFile, 'r'), 'xml')
    foundType = False
    # iterate through each packet:
    for packetXML in soup.find_all('packet'):
        # iterate through each field in the packet
        foundType = False
        for fieldXML in packetXML.find_all('field'):
            # check if the current field is a type specifier
            # -----------------Adding a flag to see if the actual type was found in the packet
            
            fullType = fieldXML.mshowname.contents[0].strip()
            typeSplitA = fullType.split(':')[0]
            typeSplitB = fullType.split(' ')[1]
            
            print "Looking at... '"+fullType+"', '"+typeSplitA+"', '"+typeSplitB+"'"
            
            try:
                if typeSplitA in TYPE_IDENTIFIERS:
                    foundType = True
                if typeSplitB in TYPE_IDENTIFIERS:
                    foundType = True
                if fullType in TYPE_IDENTIFIERS:
                    foundType = True
            except IndexError: #no more fields
                break
            
            if not foundType:
                continue
                
            # TODO: currently only one field can determine the uniqueness of a field type, will change this later
            nodeid = packetXML['nodeuniq']
            # Here check if the unmasked value exists (this means that
            # the value is likely not byte-aligned, so we need to take
            # the aligned value (given in the unmaskedvalue tag
            print "!!!!!!!!!!! found type",fullType
            if fieldXML.munmaskedvalue.contents:
                # print fieldXML.mname.contents[0],fieldXML.munmaskedvalue.contents[0];
                typeid = fullType + "=" + fieldXML.munmaskedvalue.contents[0]
            else:
                typeid = fullType + "=" + fieldXML.mvalue.contents[0]
            dataItem = (nodeid, typeid)
            # store in type mappings if it is not there yet:
            print dataItem
            if dataItem not in typeMappings:
                # give this new item an identifier (current number of elements in the array)
                typeMappings[dataItem] = len(typeMappings)
                print "insert"
            typeSequences.append(typeMappings[dataItem])
            # also add the type number to the original trace
            packetXML.attrs['type'] = typeMappings[dataItem]
            packetXML.attrs['typeuniq'] = typeid
            # ------------------------Added this break so that once found it will stop checking the rest of the packet
            # --------------------------This is where we can continue to check if we want to take another field
            # --------------------------in to consideration.
            break

    # -------------output section------------------------#
    # print an error statement if no types were found:
    if len(typeMappings) == 0:
        print "No types found in input file!"
        exit

    # write to the output file and to stdout
    out = open(outputSequenceFilename, 'w')
    for i in typeSequences:
        # sys.stdout.write(str(i)+" ")
        out.write(str(i) + " ")
    # sys.stdout.write("\n")
    out.write("\n")
    out.close()

    # -------------output the type mappings-------------#
    # create the xml tree:
    # typeMappingsXML = etree.Element("mapping_list")
    # for mapping in typeMappings:

    #	mappingElement = etree.SubElement(typeMappingsXML,"mtype", id=str(typeMappings[mapping]))
    # add each of the items that were used to create the key tuples
    #	for i in range(len(TYPE_FIELDS)):
    #		mappingElement.set(TYPE_FIELDS[i],mapping[i])

    # outputMappingXML = open('packetTypeMapping.xml','w')
    # print etree.tostring(typeMappingsXML,pretty_print='true')
    # outputMappingXML.write(etree.tostring(typeMappingsXML,pretty_print='true'))

    # -------------output the original packets with type-----#
    # print soup.prettify()
    out = open(outputPacketsTypesFilename, 'w')
    out.write(soup.prettify())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "usage: packetTypeExtractory.py <modelname> <keyword>"
        print "<modelname>"
        print " -the directory in 'models' that has 'packets.xml'\n"
        print "<keyword>"
        print " -the field that will be pivoted on\n"
        print "This program creates two files: "
        print "packetTypeSequences.txt"
        print " -this file contains the observed packet type sequences in the input file"
        print "packetTypeMapping.xml"
        print " -this file contains the mappings from numerical packet types to the unique values used as identify a unique packet type"
        sys.exit(-1)
    extractPacketType(sys.argv[1],sys.argv[2])
