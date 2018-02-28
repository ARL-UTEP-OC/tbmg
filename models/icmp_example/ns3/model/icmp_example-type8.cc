//This file was generated automatically, please do not edit unless you know exactly what you're doing.
#include "icmp_example-type0.h"
#include <stdio.h>
#include "ns3/header.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-header.h"
#include <stdint.h>
#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/ipv4-address.h"
#include "ns3/socket.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/inet-socket-address.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("icmp_example-type0");

int
icmp_exampleType0::GetTypeId (void)
{
  
  return mtype;
}

//Get/Set functions (auto-generated)
unsigned char 
icmp_exampleType0::get_icmp_type_34()
{
  
  return icmp_type_34;
}
void icmp_exampleType0::set_icmp_type_34(unsigned char val)
{
  
  icmp_type_34 = val;
}
unsigned char 
icmp_exampleType0::get_icmp_code_35()
{
  
  return icmp_code_35;
}
void icmp_exampleType0::set_icmp_code_35(unsigned char val)
{
  
  icmp_code_35 = val;
}
uint16_t
icmp_exampleType0::get_icmp_checksum_36()
{
  
  return icmp_checksum_36;
}
void icmp_exampleType0::set_icmp_checksum_36(uint16_t val)
{
  
  icmp_checksum_36 = val;
}
uint16_t
icmp_exampleType0::get_icmp_ident_38()
{
  
  return icmp_ident_38;
}
void icmp_exampleType0::set_icmp_ident_38(uint16_t val)
{
  
  icmp_ident_38 = val;
}
uint16_t
icmp_exampleType0::get_icmp_seq_40()
{
  
  return icmp_seq_40;
}
void icmp_exampleType0::set_icmp_seq_40(uint16_t val)
{
  
  icmp_seq_40 = val;
}
uint64_t
icmp_exampleType0::get_icmp_data_time_42()
{
  
  return icmp_data_time_42;
}
void icmp_exampleType0::set_icmp_data_time_42(uint64_t val)
{
  
  icmp_data_time_42 = val;
}
unsigned char* icmp_exampleType0::get_data_data_50()
{
  
  return data_data_50;
}
void icmp_exampleType0::set_data_data_50(unsigned char* val)
{
  
  memcpy(data_data_50,val,48);
}

/**
 * create a icmp_exampleType0
 */

icmp_exampleType0::icmp_exampleType0 ()//(/* any input parameters, these are all optional */);
{
  //set default values
  icmp_type_34 = 0x08;//ENTROPY: 0.0
  icmp_code_35 = 0x00;//ENTROPY: 0.0
  icmp_checksum_36 = 0x6fe9;//ENTROPY: 1.0 , see xml for other values
  icmp_ident_38 = 0x7725;//ENTROPY: 0.0
  icmp_seq_40 = 0x0001;//ENTROPY: 1.0 , see xml for other values
  icmp_data_time_42 = 0xb94c885500000000;//ENTROPY: 1.0 , see xml for other values
  unsigned char data_data_50Tmp[48] = { 0x0D,0x7B,0x03,0x00,0x00,0x00,0x00,0x00,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37 };//ENTROPY: 1.0, see xml for other values
  memcpy(data_data_50,data_data_50Tmp,48);
  mtype = 0;
}
icmp_exampleType0::~icmp_exampleType0 ()
{
  
}
  
float
icmp_exampleType0::isPacketType(unsigned char *candidate, int size)
{
  //HERE!
  //here we try to build the type of packet and depending on the results we return a confidence value
  float confidence = 0.0;

  
  //read 1 byte and store it into the variable:
  memcpy(&icmp_type_34,&candidate[0], 1);
  //std::cout << "icmp_type_34: " << (unsigned)icmp_type_34 << std::endl;
  //std::cout << " 0x" << std::hex << (int)icmp_type_34 << std::endl;
  //printf("%#010x\\n",icmp_type_34);
  
  
   if (icmp_type_34 == 0x8)
     confidence = 1.0;
  //read 1 byte and store it into the variable:
  memcpy(&icmp_code_35,&candidate[0], 1);
  //std::cout << "icmp_code_35: " << (unsigned)icmp_code_35 << std::endl;
  //std::cout << " 0x" << std::hex << (int)icmp_code_35 << std::endl;
  //printf("%#010x\\n",icmp_code_35);
  
  //read 2 byte and store it into the variable:
  Read16(&candidate[0], icmp_checksum_36);
  //std::cout << "icmp_checksum_36: " << (unsigned)icmp_checksum_36 << std::endl;
  //std::cout << " 0x" << std::hex << (int)icmp_checksum_36 << std::endl;
  //printf("%#010x\\n",icmp_checksum_36);
  
  //read 2 byte and store it into the variable:
  Read16(&candidate[0], icmp_ident_38);
  //std::cout << "icmp_ident_38: " << (unsigned)icmp_ident_38 << std::endl;
  //std::cout << " 0x" << std::hex << (int)icmp_ident_38 << std::endl;
  //printf("%#010x\\n",icmp_ident_38);
  
  //read 2 byte and store it into the variable:
  Read16(&candidate[0], icmp_seq_40);
  //std::cout << "icmp_seq_40: " << (unsigned)icmp_seq_40 << std::endl;
  //std::cout << " 0x" << std::hex << (int)icmp_seq_40 << std::endl;
  //printf("%#010x\\n",icmp_seq_40);
  
  //read 8 byte and store it into the variable:
  Read64(&candidate[0], icmp_data_time_42);
  //std::cout << "icmp_data_time_42: " << (unsigned)icmp_data_time_42 << std::endl;
  //std::cout << " 0x" << std::hex << (int)icmp_data_time_42 << std::endl;
  //printf("%#010x\\n",icmp_data_time_42);
  
  //read byte and store into the variable:
  memcpy(&data_data_50,&candidate[0], 48);
  //std::cout << "data_data_50: ";
  //for ( int i =0; i<48; i++)
	//std::cout << " 0x" << std::hex << (int)data_data_50[i];
  //std::cout << std::endl;
  //printf("%#010x\\n",data_data_50);
  
  
  //std::cout << "Original:" << std::endl;
  //for ( int i =0; i<size; i++)
  //   std::cout << " 0x" << std::hex << (int)candidate[i];
  //std::cout << std::endl;
  //TODO
  //std::cout << "confidence: " << confidence << std::endl;
  ////TODO: this should be a memcmp

  //if (icmp_type_34 == 0x8)
  //  confidence = 1.0;
  //else confidence = 0.0;

  return confidence;

}

// Writes data to buffer in little-endian format; least significant byte
// of data is at lowest buffer address
void
icmp_exampleType0::Write32 (uint8_t *buffer, const uint32_t data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  buffer[3] = (data >> 0) & 0xff;
  buffer[2] = (data >> 8) & 0xff;
  buffer[1] = (data >> 16) & 0xff;
  buffer[0] = (data >> 24) & 0xff;
}

// Writes data to buffer in little-endian format; least significant byte
// of data is at lowest buffer address
void
icmp_exampleType0::Write16 (uint8_t *buffer, const uint16_t data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  buffer[0] = (data >> 8) & 0xff;
  buffer[1] = (data >> 0) & 0xff;
}

// Writes data to buffer in little-endian format; least significant byte
// of data is at lowest buffer address
void
icmp_exampleType0::Write64 (uint8_t *buffer, uint64_t data)
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

// Read data from a little-endian formatted buffer to data
void
icmp_exampleType0::Read16 (const uint8_t *buffer, uint16_t &data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  //data = (buffer[1] << 8) + buffer[0];
  data = (buffer[0] << 8) + buffer[1];
}

// Read data from a little-endian formatted buffer to data
void
icmp_exampleType0::Read32 (const uint8_t *buffer, uint32_t &data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  data = (buffer[0] << 24) + (buffer[1] << 16) + (buffer[2] << 8) + buffer[3];
}

// Read data from a little-endian formatted buffer to data
void
icmp_exampleType0::Read64 (const uint8_t *buffer, uint64_t &data)
{
  //still not sure why we need the casts to (uint64_t) to rid the compile-time warning
  NS_LOG_FUNCTION (this << buffer << data);
  data = ((uint64_t)buffer[0] << 56) + ((uint64_t)buffer[1] << 48) + ((uint64_t)buffer[2] << 40) + ((uint64_t)buffer[3] << 32) + ((uint64_t)buffer[4] << 24) + ((uint64_t)buffer[5] << 16) + ((uint64_t)buffer[6] << 8) + (uint64_t)buffer[7];
}

Ptr<Packet> icmp_exampleType0::getPacket()
{
  uint8_t sendData[64];
  
  memcpy(&sendData[0],&icmp_type_34, sizeof(icmp_type_34));
  memcpy(&sendData[0],&icmp_code_35, sizeof(icmp_code_35));
  Write16(&sendData[0],icmp_checksum_36);
  Write16(&sendData[0],icmp_ident_38);
  Write16(&sendData[0],icmp_seq_40);
  Write64(&sendData[0],icmp_data_time_42);
  memcpy(&sendData[0],data_data_50,48);
//  std::cout << "testing packet similarity" << std::endl;
//  isPacketType(sendData, 48);

  dataPacket = Create<Packet> ((uint8_t *) sendData, 64);
  return dataPacket;
}

void icmp_exampleType0::DoDispose (void)
{

}

} // namespace ns3