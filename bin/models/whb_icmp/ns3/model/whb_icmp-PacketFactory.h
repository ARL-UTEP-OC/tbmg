//This file was generated automatically, please do not edit unless you know exactly what you're doing.
#ifndef WHB_ICMP_PACKET_FACTORY_H
#define WHB_ICMP_PACKET_FACTORY_H

//now include the packet types associated with this model:
#include "ns3/whb_icmp-type1.h"
#include "ns3/whb_icmp-type0.h"
#include "ns3/log.h"
#include "whb_icmp-PacketType.h"

namespace ns3 {
/**
 * \ingroup whb_icmpPacketFactory
 * \brief 
 *
 * Note: 
 */
class whb_icmpPacketFactory
{
public:

enum PacketTypes{

      whb_icmp_type0 = 0,
      whb_icmp_type0 = 0,
	   num_types
};
	static whb_icmpPacketType* createPacketType (int packetType);

private:
	virtual void DoDispose (void);
};
}

#endif //WHB_ICMP_PACKET_FACTORY_H