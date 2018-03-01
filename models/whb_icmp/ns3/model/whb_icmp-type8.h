#ifndef WHB_ICMP_TYPE_0_H
#define WHB_ICMP_TYPE_0_H
#include "ns3/whb_icmp-PacketType.h"
#include "ns3/application.h"
#include "ns3/traced-callback.h"
#include "ns3/nstime.h"
#include "ns3/average.h"
#include "ns3/simulator.h"
#include <map>

namespace ns3 {
/**
 * \ingroup whb_icmpType0
 * \brief 
 *
 * Note: 
 */
class whb_icmpType0 : public whb_icmpPacketType
{
public:

  int GetTypeId (void);
  //getters and setters functions (auto-generated)
  uint8_t get_icmp_type_34();
  void set_icmp_type_34(unsigned char val);
  uint8_t get_icmp_code_35();
  void set_icmp_code_35(unsigned char val);
  uint16_t get_icmp_checksum_36();
  void set_icmp_checksum_36(uint16_t val);
  uint16_t get_icmp_ident_38();
  void set_icmp_ident_38(uint16_t val);
  uint16_t get_icmp_seq_40();
  void set_icmp_seq_40(uint16_t val);
  uint64_t get_icmp_data_time_42();
  void set_icmp_data_time_42(uint64_t val) ;
  unsigned char* get_data_data_50();
  void set_data_data_50(unsigned char* val);

  /**
   * create a whb_icmpType
   */
  whb_icmpType0 (/* any input parameters, these are all optional */);
  virtual ~whb_icmpType0 ();

  float isPacketType(unsigned char* candidate, int size);

  Ptr<Packet> getPacket(void);

private:
 
    /**
   * \brief Writes data to buffer in little-endian format.
   *
   * Least significant byte of data is at lowest buffer address
   *
   * \param buffer the buffer to write to
   * \param data the data to write
   */
  void Write16 (uint8_t *buffer, const uint16_t data);

  /**
   * \brief Writes data to buffer in little-endian format.
   *
   * Least significant byte of data is at lowest buffer address
   *
   * \param buffer the buffer to write to
   * \param data the data to write
   */
  void Write32 (uint8_t *buffer, const uint32_t data);

    /**
   * \brief Writes data from a little-endian formatted buffer to data.
   *
   * \param buffer the buffer to read from
   * \param data the read data
   */
   void Write64 (uint8_t *buffer, const uint64_t data);

  /**
   * \brief Read data from a little-endian formatted buffer to data.
   *
   * \param buffer the buffer to read from
   * \param data the read data
   */
  void Read16 (const uint8_t *buffer, uint16_t &data);

  /**
   * \brief Writes data from a little-endian formatted buffer to data.
   *
   * \param buffer the buffer to read from
   * \param data the read data
   */
  void Read32 (const uint8_t *buffer, uint32_t &data);

  /**
   * \brief Writes data from a little-endian formatted buffer to data.
   *
   * \param buffer the buffer to read from
   * \param data the read data
   */
  void Read64 (const uint8_t *buffer, uint64_t &data);

  void DoDispose (void);
  
  //variables (auto-generated)
  int mtype;
  unsigned char icmp_type_34;
  unsigned char icmp_code_35;
  uint16_t icmp_checksum_36;
  uint16_t icmp_ident_38;
  uint16_t icmp_seq_40;
  uint64_t icmp_data_time_42;
  unsigned char data_data_50[48];
  
  Ptr<Packet> dataPacket;

};

} // namespace ns3

#endif /* _TYPE_0_H */