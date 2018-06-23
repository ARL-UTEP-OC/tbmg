//This file was generated automatically, please do not edit unless you know exactly what you're doing.
#ifndef ICMP_EXAMPLE_PACKET_FACTORY_H
#define ICMP_EXAMPLE_PACKET_FACTORY_H

//now include the packet types associated with this model:
#include "ns3/icmp_example-type1.h"
#include "ns3/icmp_example-type0.h"
#include "ns3/log.h"
#include "icmp_example-PacketType.h"

namespace ns3 {
/**
 * \ingroup icmp_examplePacketFactory
 * \brief 
 *
 * Note: 
 */
class icmp_examplePacketFactory
{
public:

enum PacketTypes{

      icmp_example_type0 = 0,
      icmp_example_type0 = 0,
	   num_types
};
	static icmp_examplePacketType* createPacketType (int packetType);

private:
	virtual void DoDispose (void);
};
}

#endif //ICMP_EXAMPLE_PACKET_FACTORY_H