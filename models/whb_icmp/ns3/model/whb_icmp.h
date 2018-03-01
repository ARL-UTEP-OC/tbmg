#ifndef WHB_ICMP_H
#define WHB_ICMP_H

#include "ns3/application.h"
#include "ns3/traced-callback.h"
#include "ns3/nstime.h"
#include "ns3/average.h"
#include "ns3/simulator.h"
#include <map>
#include "whb_icmp-PacketFactory.h"
#include "ns3/whb_icmp-Grammar.h"

namespace ns3 {

class Socket;

/**
 * \ingroup applications
 * \defgroup whb_icmp whb_icmp
 */

/**
 * \ingroup whb_icmp
 * \brief 
 *
 * Note: 
 */
class whb_icmp : public Application
{
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  /**
   * create a 
   */
  whb_icmp ();
  virtual ~whb_icmp ();

private:

  // inherited from Application base class.
  virtual void StartApplication (void);
  virtual void StopApplication (void);
  virtual void DoDispose (void);
  /**
   * \brief Return the application ID in the node.
   * \returns the application id
   */
  uint32_t GetApplicationId (void) const;
  /**
   * \brief Receive an TODO
   * \param socket the receiving socket
   *
   * This function is called by lower layers through a callback.
   */
  void Receive (Ptr<Socket> socket);
  /**
   * \brief 
   */
  void Send ();

  /// Remote address
  Ipv4Address m_remote;
  /// Wait  interval seconds between sending each packet
  Time m_interval;
  /**
   * Specifies  the number of data bytes to be sent.
   */
  uint32_t m_size;
  /// The socket we send packets from
  Ptr<Socket> m_socket;
  /// ICMP ECHO sequence number
  uint16_t m_seq;
  /// TracedCallback for RTT measured by ICMP ECHOs
  TracedCallback<Time> m_traceRtt;
  /// produce extended output if true
  bool m_verbose;
  /// received packets counter
  uint32_t m_recv;
  /// Start time (when packet was sent)
  Time m_started;
  /// Average rtt is ms
  Average<double> m_avgRtt;
  /// Next packet will be sent
  EventId m_next;
  /// All sent but not answered packets. Map icmp seqno -> when sent
  std::map<uint16_t, Time> m_sent;
  /// Grammar state machine associated with the model
  whb_icmpStateMachine *sm;
  /// will instantiate communication if true
  bool m_instantiator;
  /// id associated with this model instance
  uint32_t m_id;
};

} // namespace ns3

#endif /* WHB_ICMP_H */