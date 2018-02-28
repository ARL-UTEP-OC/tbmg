//This file was generated using xmlToNs3Scenario.py, please do not edit unless you know exactly what you're doing.
#include <fstream>
#include <string>
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/icmp_example.h"
#include "ns3/icmp_example-helper.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("Input icmp_example");

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
    icmp_exampleHelper icmp_exampleHelperHelper0 = icmp_exampleHelper(Ipv4Address("10.0.0.2"));
    icmp_exampleHelperHelper0.SetAttribute("Verbose", BooleanValue(true));
    icmp_exampleHelperHelper0.SetAttribute("Interval", TimeValue(Seconds(10)));
    icmp_exampleHelperHelper0.SetAttribute("Instantiator", BooleanValue(true));
    icmp_exampleHelperHelper0.SetAttribute("ID", UintegerValue(1));
    ApplicationContainer apps = icmp_exampleHelperHelper0.Install(nodes.Get(0));
    apps.Start(Seconds (0.0));
    apps.Stop(Seconds (1.0));
    
    //Create the model for the second node:
    icmp_exampleHelper icmp_exampleHelperHelper1 = icmp_exampleHelper(Ipv4Address("10.0.0.1"));
    icmp_exampleHelperHelper1.SetAttribute("Verbose", BooleanValue(true));
    icmp_exampleHelperHelper1.SetAttribute("Interval", TimeValue(Seconds(1)));
    icmp_exampleHelperHelper1.SetAttribute("Instantiator", BooleanValue(false));
    icmp_exampleHelperHelper0.SetAttribute("ID", UintegerValue(2));
    apps = icmp_exampleHelperHelper1.Install(nodes.Get(1));

    apps.Start(Seconds (0.0));
    apps.Stop(Seconds (1.0));

    NS_LOG_INFO("Run Simulation");
    Simulator::Run();
    Simulator::Destroy();
    NS_LOG_INFO("Done...");
}