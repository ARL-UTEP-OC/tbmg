//This file was generated automatically, please do not edit unless you know exactly what you're doing.
#include "whb_icmp-PacketFactory.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("whb_icmp-PacketFactory");

whb_icmpPacketType*
whb_icmpPacketFactory::createPacketType (int packetType)
{

  
  if (packetType == whb_icmp_type0)
	return new whb_icmpType0();
  
  
  else if (packetType == whb_icmp_type0)
	return new whb_icmpType0();
  
  return 0;
}
}