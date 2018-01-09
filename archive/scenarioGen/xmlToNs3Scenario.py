#!/usr/bin/python
#Creating C++ NS-3 Simulation Using python

from bs4 import BeautifulSoup
import sys
#Importing XML tree/Node count
import xml.etree.ElementTree as ET

modelName = str(sys.argv[1])
file = open(modelName + '.cc', 'a')
sourceCode = ""

tree = ET.parse('scenarioStandardizedXMLFile.xml')
network = tree.getroot()
count = 0
for node in network.iter('node'):
    count += 1
numOfNodes = count

file = open(modelName + '.cc', 'w')
sourceCode += '''//This file was generated using xmlToNs4Scenario.py, please do not edit unless you know exactly what you're doing.
#include <fstream>
#include <string>
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/'''+modelName+'''.h"
#include "ns3/'''+modelName+'''-helper.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("Input '''+modelName+'''");

int main(int argc, char** argv){
        GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));
        NS_LOG_INFO("Creating Nodes");''' + '\n'

#Creating and setting nodes/node container
for x in range (numOfNodes):
    nodeMake = 'Ptr<Node> n' + `x` + ' = CreateObject<Node>();'
    sourceCode += '\t' + nodeMake + '\n'

sourceCode += ' \n      NodeContainer nodes('
y=0
for y in range (numOfNodes-1):
    nodeNum = 'n' + `y` + ','
    sourceCode += nodeNum
nodeNum = 'n' + `y+1`
sourceCode += nodeNum
sourceCode += ');\n'


sourceCode += '''
    NS_LOG_INFO ("Create IPv4 Internet Stack");
        InternetStackHelper internetv4;
        internetv4.Install(nodes);

        NS_LOG_INFO("Create channels.");
        CsmaHelper csma;
        csma.SetChannelAttribute("DataRate", DataRateValue (50000000));
        csma.SetChannelAttribute("Delay", TimeValue (MilliSeconds(100)));
        NetDeviceContainer devices = csma.Install(nodes);
        csma.EnablePcapAll("allCapture", true);

        '''

#xml parser for protocol
flowArray = []

network = tree.getroot()
for node in network.findall('node'):
    macsrc = node.find('macsrc').text
    flow = node.find('flow')
    for flow in node.findall('flow'):
        protocol = flow.find('protocol').text
        ipsrc = flow.find('ipsrc').text
        ipdst = flow.find('ipdst').text
        macdst = flow.find('macdst').text
        print 'Protocol: ' + protocol
        print 'Mac Source: ' + macsrc
        print 'IP Source: ' + ipsrc
        print 'IP Destination: ' + ipdst
        print 'MAC Destination: ' + macdst
        print ''
        flowfields = (protocol,macsrc,ipsrc,ipdst,macdst)
        flowArray.append(flowfields)
    print "Fields: %s" % (flowfields,)
    print ''

#Obtaining base IP
e = "0"
a,b,c,d = ipsrc.split(".")
ipsrcbase = a+'.'+b+'.'+c+'.'+e
print 'This is the base IP: ' + ipsrcbase

#Setting base IP
sourceCode += '''
    Ipv4AddressHelper ipv4;
        ipv4.SetBase("'''+"0.0.0.0"+'''", "1.0.0.0");
        Ipv4InterfaceContainer ipv4IntC;\n \t

'''

#Setting Static IP's
index = 0
for each in flowArray:
    test  = '\tIpv4Address ip'+ `index + 1` + '("' +flowArray[index][2] + '");\n'
    test2 = '''\tipv4.AssignIpToithNetDevice(devices,ipv4IntC,'''+`index`+''', ip'''+ `index + 1`+''');'''
    sourceCode += test
    sourceCode += test2 + '\n'
    index += 1

#Hard coded ping code
sourceCode += '''
        '''+modelName+'''Helper '''+modelName+'''HelperHelper = '''+modelName+'''Helper(ip2);
    '''+modelName+'''HelperHelper.SetAttribute("Verbose", BooleanValue(true));
    '''+modelName+'''HelperHelper.SetAttribute("Interval", TimeValue(Seconds(1)));
    ApplicationContainer apps = '''+modelName+'''HelperHelper.Install(nodes.Get(0));

    apps.Start(Seconds (0.0));
    apps.Stop(Seconds (1.0));

    NS_LOG_INFO("Run Simulation");
    Simulator::Run();
    Simulator::Destroy();
    NS_LOG_INFO("Done...");
}'''
file.write(sourceCode)
file.close()
print 'Done!'
