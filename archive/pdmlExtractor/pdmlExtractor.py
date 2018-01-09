#!/usr/bin/python
#version 2: Outputs an xml file with each node and its pertaining protocols. This will be used to produce the simulation .cc file.
from classes.flowClass import Flow
from classes.nodeClass import Node
from lxml import etree

import sys
import subprocess
import datetime
import time
import os


#method to traverse through each parent of the tree
def traverse(node, packetXML):
    global fields
    root = node
    if len(root):
        for subchild in root:
            mname = subchild.get('name')
            childName = subchild.get('showname')
            size = subchild.get('size')
            show = subchild.get('show')
            pos = subchild.get('pos')
            value = subchild.get('value')
            unmaskedvalue = subchild.get('unmaskedvalue')
            if mname == None or mname == "":
                mname = "unspecified"
            fields.write(";mname, "+mname+"\n")
            if childName == None or childName == "":
                childName = "unspecified"
            if size == None or size == "":
                size = "unspecified"
            fields.write("mshowname,"+ childName + ";size, "+size)
            if show == None or show == "":
                show = "unspecified"
            fields.write("; show, "+show)
            if pos == None or pos == "":
                pos = "unspecified"
            fields.write(";pos, "+pos)
            if value == None or value == "":
                value = "unspecified"
            fields.write(";value, "+value)
            if unmaskedvalue == None or unmaskedvalue == "":
                unmaskedvalue = "unspecified"
            fields.write(";unmaskedvalue, "+value)


            fieldXML = etree.SubElement(packetXML,"field")
            etree.SubElement(fieldXML,"mshowname").text = childName
            etree.SubElement(fieldXML,"msize").text = size
            etree.SubElement(fieldXML,"mshow").text = show
            etree.SubElement(fieldXML,"mpos").text = pos
            etree.SubElement(fieldXML,"mvalue").text = value
            etree.SubElement(fieldXML,"munmaskedvalue").text = unmaskedvalue
            etree.SubElement(fieldXML,"mname").text = mname
#

            traverse(subchild, packetXML)      #a

#               traverse(root[0])
    return

def extractString(s):
    temp = s[s.find("(")+1:s.find(")")]
    return temp

def convertTime(s):
    l, r = s.split(':')
    left, right = r.split()
    left = float(left)
    t = datetime.datetime.fromtimestamp(left).strftime("%Y-%m-%d %H:%M:%S:%f")
    return t

def printArray(tree):
    for node in tree:
        print(node)

name = None
def produceXML(NodeArray):
    checkIP = True
    global name

    nodeFile= open(name+"/scenarioStandardizedXMLFile.xml", "w+")

    nodeFile.write("<network>\n")
    nodeNum = 0
    for allNodes in NodeArray:
        protNum = 0
        nodeFile.write("  <node number = '")
        nodeFile.write(str(nodeNum)+"'>\n")
        nodeFile.write("     <macsrc>")
        nodeFile.write(allNodes.macsrc)
        nodeFile.write("</macsrc>\n")
        for protos in allNodes.protocol:
            nodeFile.write("     <flow>\n")
            nodeFile.write("       <protocol>")
            nodeFile.write(protos)
            nodeFile.write("</protocol>\n")
            nodeFile.write("       <macdst>")
            nodeFile.write(str(allNodes.macdst[protNum]))
            nodeFile.write("</macdst>\n")
            try:
                ipsrc = allNodes.ipsrc[protNum]
                ipdst = allNodes.ipdst[protNum]
            except (RuntimeError, TypeError, NameError):
                checkIP = False
            if ipsrc != None:
                nodeFile.write("       <ipsrc>")
                nodeFile.write(str(ipsrc))
                nodeFile.write("</ipsrc>\n")
                nodeFile.write("       <ipdst>")
                nodeFile.write(str(ipdst))
                nodeFile.write("</ipdst>\n")
            nodeFile.write("       <time>\n")
            nodeFile.write("          <first>")
            nodeFile.write(allNodes.time[protNum])
            nodeFile.write("</first>\n")
            nodeFile.write("          <last>")
            nodeFile.write(allNodes.ltime[protNum])
            nodeFile.write("</last>\n")
            nodeFile.write("          <count>")
            nodeFile.write(str(allNodes.count[protNum]))
            nodeFile.write("</count>\n")
            nodeFile.write("       </time>\n")
            nodeFile.write("     </flow>\n")

            protNum += 1
        nodeFile.write("  </node>\n")
        nodeNum += 1
    nodeFile.write("</network>\n")
    nodeFile.close()


def xmlFlow(flowArr):
    global name
    flowFile= open(name+"/xmlFlow.xml", "w+")
    flowFile.write("<root>\n")
    for flow in flowArr:
        macsrc = flow.macsr
        protocol = flow.protocol
        macdst = flow.macdst
        time = flow.time
        checkIP = True
        try:
            ipsrc = flow.ipsr
            ipdst = flow.ipds
        except (ValueError, TypeError):
            checkIP = False
        if ipsrc != None:
            ips = '''<ipsrc>'''+ipsrc+'''</ipsrc>
<ipdst>'''+ipdst+'''</ipdst>'''

        else:
            ips = " "
        inf = '''   <flow>
<protocol>'''+protocol+'''</protocol>
<macsrc>'''+str(macsrc)+'''</macsrc>
<macdst>'''+str(macdst)+'''</macdst>
'''+ips+'''
<time>'''+time+'''</time>
</flow>
'''
        flowFile.write(inf)
    flowFile.write("</root>")
    flowFile.close()




NodeArray = []
FlowCount = 0
NodeCount = 0
def createNodes(flows):
    global FlowCount
    global NodeCount
    global NodeArray
    checkIP = True
    protoFlows = flows
    #stored = False
    for flow in protoFlows:
        FlowCount += 1
        macsrc = flow.macsr
        protocol = flow.protocol
        macdst = flow.macdst
        time = flow.time
        stored = False
        try:
            ipsrc = flow.ipsr
            ipdst = flow.ipds
        except ValueError:
            checkIP = False

        if len(NodeArray) == 0:
            if checkIP:
                newNode = Node(macsrc)
                #add protocol to node here
                newNode.addProtocol(protocol, ipsrc, ipdst, macdst, time)
            else:
                newNode = Node(macsrc)
                #add protocol to node here
                newNode.addProtocol(protocol, macdst, time)
            NodeCount += 1

            newNode.newcount(1)
            newNode.lastTime(time)
            NodeArray.append(newNode)

        else:
            for node in NodeArray:
                protoFound = False
                if node.macsrc == macsrc:
                    protoCount = 0
                    #check stored nodes protocol
                    for proto in node.protocol:

                        if proto == protocol and node.macdst[protoCount] == macdst:

                            protoFound = True
                            node.ltime[protoCount] = time
                            node.count[protoCount] += 1
                            break

                        protoCount += 1

                    if protoFound == False:

                        if checkIP:
                            node.addProtocol(protocol, ipsrc, ipdst, macdst, time)

                        else:
                            node.addProtocol(protocol, macdst, time)

                        node.lastTime(time)
                        node.newcount(1)






                    stored = True
                    break
            if stored == False:
                if checkIP:
                    newNode = Node(macsrc)
                    #add protocol to node here
                    newNode.addProtocol(protocol, ipsrc, ipdst, macdst, time)
                else:
                    newNode = Node(macsrc)
                    #add protocol to node here
                    newNode.addProtocol(protocol, macdst, time)

                newNode.newcount(1)
                newNode.lastTime(time)
                NodeArray.append(newNode)
                NodeCount += 1





#getting argument passed in

total = len(sys.argv)
if total < 4:
    print 'missing argument'
    print 'python pcapParser.py <pcap file> <protocol name> <model name>'
    sys.exit(2)

file = str(sys.argv[1])
protocol = str(sys.argv[2])
try:
    other = str(sys.argv[4])
except (RuntimeError, TypeError, NameError, IndexError):
    other = None
#end of getting protocol

#creating pdml file
cmd = "/usr/bin/tshark -r "+file+" -T pdml -E separator=, > "+file+".pdml"
subprocess.call(cmd, shell=True, stderr=subprocess.PIPE)

#array to store Nodes
flowArray = []
nodeNum = 0
#creating a directory to store all the output files
name = str(sys.argv[3])

packetsXML = etree.Element("packets", id=name)

#name = str(datetime.datetime.now())
#left, name = name.split()
#os.mkdir(str(name))

fields = open(name+"/fields.txt", "w+")

#importing XML pcap file
import xml.etree.ElementTree as ET
tree = ET.parse(file+".pdml")
root = tree.getroot()

macsrc = " "
macdst = " "
ipsrc = " "
ipdst = " "

found = 0
foundip = False
for packets in root.findall('packet'):
    count = 0

    for child in packets:

        #print child.attrib['name']
        if child.attrib['name'] == protocol:
            protoName = child.attrib['name']
            for child in packets:
                if child.attrib['name'] == "frame":
                    for field in child:
                        if field.attrib['name'] == "frame.time_epoch":
                            time = field.get('showname')
                            time = convertTime(time)

                if child.attrib['name'] == "eth":
                    for field in child:
                        if field.attrib['name'] == "eth.dst":
                            macdst = field.get('showname')
                            macdst = extractString(macdst)
                        if field.attrib['name'] == "eth.src":
                            macsrc = field.get('showname')
                            macsrc = extractString(macsrc)
                if child.attrib['name'] == "ip":
                    foundip = True
                    for field in child:
                        if field.attrib['name'] == "ip.src":
                            ipsrc = field.get('showname')
                            ipsrc = extractString(ipsrc)
                        if field.attrib['name'] == "ip.dst":
                            ipdst = field.get('showname')
                            ipdst = extractString(ipdst)

            print "Protocol Name: "+protoName
            if macdst:
                print "Mac Address Source: "+macsrc
                print "Mac Address Destination: "+macdst
                flowObj = Flow(protoName, macsrc, macdst)

            if foundip:
                print "IP Address Source: "+ ipsrc
                print "IP Address Destination: "+ipdst
                flowObj.addIpSrc(ipsrc)
                flowObj.addIpDst(ipdst)
            flowObj.addTime(time)
            nodeNum += 1
#JA added
#*****************************************************************************
#Modified 10/08/15 Testing with TCP




            fields.write(macsrc+";"+macdst+";"+ipsrc+";"+ipdst+";"+protoName+"\n")

            fields.write(macdst+";"+protoName+"\n")
#**********************************************************************


            packetXML = etree.SubElement(packetsXML,"packet")
            nodeuniq = 'macsrc='+macsrc+";"+'macdst='+macdst+";"+'ipsrc='+ipsrc+";"+'ipdst='+ipdst+";"+'protoName='+protoName
            packetXML.set('nodeuniq',nodeuniq)

            flowArray.append(flowObj)

            for child in packets[count]:

                mname = child.get('name')
                childName = child.get('showname')
                size = child.get('size')
                show = child.get('show')
                pos = child.get('pos')
                value = child.get('value')
                unmaskedvalue = child.get('unmaskedvalue')
                if mname == None or mname == "":
                    name = "unspecified"
                fields.write(";mname, "+mname+"\n")
                if childName == None or childName == "":
                    childName = "unspecified"
                if size == None or size == "":
                    size = "unspecified"
                fields.write("mshowname,"+ childName + ";size, "+size)
                if show == None or show == "":
                    show = "unspecified"
                fields.write("; show, "+show)
                if pos == None or pos == "":
                    pos = "unspecified"
                fields.write(";pos, "+pos)
                if value == None or value == "":
                    value = "unspecified"
                fields.write(";value, "+value)
                if unmaskedvalue == None or unmaskedvalue == "":
                    unmaskedvalue = "unspecified"
                fields.write(";unmaskedvalue, "+value)

                fieldXML = etree.SubElement(packetXML,"field")
                etree.SubElement(fieldXML,"mshowname").text = childName
                etree.SubElement(fieldXML,"msize").text = size
                etree.SubElement(fieldXML,"mshow").text = show
                etree.SubElement(fieldXML,"mpos").text = pos
                etree.SubElement(fieldXML,"mvalue").text = value
                etree.SubElement(fieldXML,"munmaskedvalue").text = unmaskedvalue
                etree.SubElement(fieldXML,"mname").text = mname

                traverse(child, packetXML)
            found += 1
            print " "
            fields.write(" \n")
        count += 1
fields.close()
#printArray(flowArray)
if found == 0:
    print "Protocol Not Found"
else:
    #printArray(flowArray)
    #print flowArray[1] == flowArray[3]
    createNodes(flowArray)
    produceXML(NodeArray)
    printArray(flowArray)
    #if protocol == "icmp":
    #       callPingSim()
#if other == "-f":
#    xmlFlow(flowArray)
#elif other != None:
#       print other+ " is not an existing argument"

print etree.tostring(packetsXML,pretty_print='true')

outputPacketsXML = open(name+'/packets.xml','w')
print etree.tostring(packetsXML,pretty_print='true')
outputPacketsXML.write(etree.tostring(packetsXML,pretty_print='true'))
