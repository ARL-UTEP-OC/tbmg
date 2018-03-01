//auto-generated
#include "whb_icmp-PacketType.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("whb_icmp-PacketType");

// Writes data to buffer in little-endian format; least significant byte
// of data is at lowest buffer address
void
whb_icmpPacketType::Write32 (uint8_t *buffer, const uint32_t data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  buffer[0] = (data >> 0) & 0xff;
  buffer[1] = (data >> 8) & 0xff;
  buffer[2] = (data >> 16) & 0xff;
  buffer[3] = (data >> 24) & 0xff;
}

// Writes data to buffer in little-endian format; least significant byte
// of data is at lowest buffer address
void
whb_icmpPacketType::Write16 (uint8_t *buffer, const uint16_t data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  buffer[0] = (data >> 8) & 0xff;
  buffer[1] = (data >> 0) & 0xff;
}

// Writes data to buffer in little-endian format; least significant byte
// of data is at lowest buffer address
void
whb_icmpPacketType::Write64 (uint8_t *buffer, uint64_t data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  buffer[7] = (data >> 0) & 0xff;
  buffer[6] = (data >> 8) & 0xff;
  buffer[5] = (data >> 16) & 0xff;
  buffer[4] = (data >> 24) & 0xff;
  buffer[3] = (data >> 32) & 0xff;
  buffer[2] = (data >> 40) & 0xff;
  buffer[1] = (data >> 48) & 0xff;
  buffer[0] = (data >> 56) & 0xff;
}

// Writes data from a little-endian formatted buffer to data
void
whb_icmpPacketType::Read16 (const uint8_t *buffer, uint16_t &data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  //data = (buffer[1] << 8) + buffer[0];
  data = (buffer[0] << 8) + buffer[1];
}

// Writes data from a little-endian formatted buffer to data
void
whb_icmpPacketType::Read32 (const uint8_t *buffer, uint32_t &data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  data = (buffer[0] << 24) + (buffer[1] << 16) + (buffer[2] << 8) + buffer[3];
}

// Writes data from a little-endian formatted buffer to data
void
whb_icmpPacketType::Read64 (const uint8_t *buffer, uint64_t &data)
{
  //still not sure why we need the casts to (uint64_t) to rid the compile-time warning
  NS_LOG_FUNCTION (this << buffer << data);
  data = ((uint64_t)buffer[0] << 56) + ((uint64_t)buffer[1] << 48) + ((uint64_t)buffer[2] << 40) + ((uint64_t)buffer[3] << 32) + ((uint64_t)buffer[4] << 24) + ((uint64_t)buffer[5] << 16) + ((uint64_t)buffer[6] << 8) + (uint64_t)buffer[7];
}


} // namespace ns3