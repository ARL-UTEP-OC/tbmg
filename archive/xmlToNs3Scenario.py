#!/usr/bin/python
#Creates a C++ NS-3 Model Using python
from bs4 import BeautifulSoup
from jinja2 import Template
import sys

xmlFilename = sys.argv[1]
modelName = sys.argv[2]

soup = BeautifulSoup(open(xmlFilename,'r'), 'xml')

def generateFile(filename):
	scenarioFile = Template('''
//This file was generated using xmlToNs3Scenario.py, please do not edit unless you know exactly what you're doing.
#include <fstream>
#include <string>
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/{{jinjaModelName}}.h"
#include "ns3/{{jinjaModelName}}-helper.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("Input {{jinjaModelName}}");

int main(int argc, char** argv){
    GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));
    NS_LOG_INFO("Creating Nodes");
	Ptr<Node> n0 = CreateObject<Node>();
	Ptr<Node> n1 = CreateObject<Node>();
 
    NodeContainer nodes(n0,n1);

    NS_LOG_INFO ("Create IPv4 Internet Stack");
    InternetStackHelper internetv4;
    internetv4.Install(nodes);

    NS_LOG_INFO("Create channels.");
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue (50000000));
    csma.SetChannelAttribute("Delay", TimeValue (MilliSeconds(100)));
    
    NetDeviceContainer devices = csma.Install(nodes);
    csma.EnablePcapAll("allCapture", true);

        
    Ipv4AddressHelper ipv4("10.0.0.0", Ipv4Mask("255.255.255.0"), "0.0.0.1");
    Ipv4InterfaceContainer ipv4IntC;
 	
	ipv4.Assign(devices);
		
	//Create the model for the first node:
    {{jinjaModelName}}Helper {{jinjaModelName}}HelperHelper0 = {{jinjaModelName}}Helper(Ipv4Address("10.0.0.2"));
    {{jinjaModelName}}HelperHelper0.SetAttribute("Verbose", BooleanValue(true));
    {{jinjaModelName}}HelperHelper0.SetAttribute("Interval", TimeValue(Seconds(10)));
    {{jinjaModelName}}HelperHelper0.SetAttribute("Instantiator", BooleanValue(true));
    {{jinjaModelName}}HelperHelper0.SetAttribute("ID", UintegerValue(1));
    ApplicationContainer apps = {{jinjaModelName}}HelperHelper0.Install(nodes.Get(0));
    apps.Start(Seconds (0.0));
    apps.Stop(Seconds (1.0));
    
    //Create the model for the second node:
    {{jinjaModelName}}Helper {{jinjaModelName}}HelperHelper1 = {{jinjaModelName}}Helper(Ipv4Address("10.0.0.1"));
    {{jinjaModelName}}HelperHelper1.SetAttribute("Verbose", BooleanValue(true));
    {{jinjaModelName}}HelperHelper1.SetAttribute("Interval", TimeValue(Seconds(1)));
    {{jinjaModelName}}HelperHelper1.SetAttribute("Instantiator", BooleanValue(false));
    {{jinjaModelName}}HelperHelper0.SetAttribute("ID", UintegerValue(2));
    apps = {{jinjaModelName}}HelperHelper1.Install(nodes.Get(1));

    apps.Start(Seconds (0.0));
    apps.Stop(Seconds (1.0));

    NS_LOG_INFO("Run Simulation");
    Simulator::Run();
    Simulator::Destroy();
    NS_LOG_INFO("Done...");
}
''')
	ofile = open(filename, 'w')
	ofile.write(scenarioFile.render(jinjaModelName=modelName, todo='TODO'))
	#print scenarioFile.render(jinjaModelName=modelName, todo='TODO')

def main():
	outputPath = modelName+"/"+modelName+"Scenario/"
	generateFile(outputPath+modelName+".cc")
	
if __name__ == "__main__":
	main()