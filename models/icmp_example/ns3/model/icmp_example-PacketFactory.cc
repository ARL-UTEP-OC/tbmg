//This file was generated automatically, please do not edit unless you know exactly what you're doing.
#include "icmp_example-PacketFactory.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("icmp_example-PacketFactory");

icmp_examplePacketType*
icmp_examplePacketFactory::createPacketType (int packetType)
{

  
  if (packetType == icmp_example_type0)
	return new icmp_exampleType0();
  
  
  else if (packetType == icmp_example_type0)
	return new icmp_exampleType0();
  
  return 0;
}
}