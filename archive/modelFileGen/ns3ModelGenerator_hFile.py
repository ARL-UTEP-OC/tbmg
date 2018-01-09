#!/usr/bin/python
#Creates a C++ NS-3 Model Using python
from bs4 import BeautifulSoup
from jinja2 import Template
import sys

xmlFilename = sys.argv[1]
modelName = sys.argv[2]

soup = BeautifulSoup(open(xmlFilename,'r'), 'xml')

def generateFile(filename, mid):
	myFields = []
	packetTypeUnique = []
	totalPacketSize = 0
	currFieldPos = 0
	for myType in soup.find_all('mtype',id=mid):
		var = myType['typeuniq'].split('=')[0].replace(".","_").encode('ascii').strip()
		val = int(myType['typeuniq'].split('=')[1].replace(".","_").encode('ascii'))
		packetTypeUnique.append((var, val))
		currPacketSize = 0
		for myField in myType.find_all('mfield'):
		#only include the field if its byte location has not been specified by another field:
			if myField.msize.contents[0].split(';')[0]!='unspecified' and myField.msize.contents[0].split(';')[0]!='0' and len(myField.mvalue.contents) > 0 and myField.mvalue.contents[0].split(';')[0]!='unspecified':
				totalPacketSize += int(myField.msize.contents[0].split(';')[0])
				#fix up the mname field:
				mname = myField.mname.contents[0].split(';')[0].replace("(","").replace(")","").replace(" ","_").replace(".","_")
				#fix up the vocab field to work with C++ (hex bytes)
				mvalue = ""
				mvalueItem = myField.mvalue.contents[0].split(';')[0]
				if mvalueItem.strip() != ';' and mvalueItem.strip() != '':
					if myField.msize.contents[0].split(';')[0] == '1' or myField.msize.contents[0].split(';')[0] == '2' or myField.msize.contents[0].split(';')[0] == '4' or myField.msize.contents[0].split(';')[0] == '8':
						mvalue="0x"+mvalueItem
					else:
						mvalueItem = mvalueItem.decode("hex")
						mvalue=''.join( [ "0x%02X " % ord( x ) for x in mvalueItem ] ).strip()
				if int(myField.mpos.contents[0].split(';')[0]) == currFieldPos or len(myFields) == 0:
					#print 'NEW: adding new',myField.mname.contents[0].split(';')[0].replace("(","").replace(")","").replace(" ","_").replace(".","_")
					myFields.append((myType['id'],mname, myField.msize.contents[0].split(';')[0], myField.mentropy.contents[0].split(';')[0], mvalue, myField.mpos.contents[0].split(';')[0]))
					currFieldPos = int(myField.mpos.contents[0].split(';')[0])+int(myField.msize.contents[0].split(';')[0])
				elif int(myField.mpos.contents[0].split(';')[0]) < currFieldPos:
					#print 'LESS: found pos less than existing: ',myField.mname.contents[0].split(';')[0].replace("(","").replace(")","").replace(" ","_").replace(".","_")
					#print "TEST: ", myField.msize.contents[0].split(';')[0],'>',int(myFields[-1][2])
					if int(myField.msize.contents[0].split(';')[0]) > int(myFields[-1][2]):
						#print 'RES: replacing because curr is sample pos and bigger than previous'						
						#print 'before:',myFields[-1]						
						rpId = myType['id']
						rpName = mname.split(';')[0]
						rpSize = myField.msize.contents[0].split(';')[0]
						rpEnt = myField.mentropy.contents[0].split(';')[0]
						rpVal = calcStrOr(myFields[-1][4],int(myFields[-1][2]),myField.mvalue.contents[0].split(';')[0],int(rpSize))
						rpPos = myField.mpos.contents[0].split(';')[0]
						myFields[-1] = (rpId, rpName, rpSize, rpEnt, rpVal, rpPos)
						currFieldPos = int(rpPos)+int(rpSize)
						#print 'after:',myFields[-1]
					else:
						{}#print 'RES: not bigger'
				else:
					{}#print 'IGNORED:',myField.mname.contents[0].split(';')[0].replace("(","").replace(")","").replace(" ","_").replace(".","_")'

	hFile = Template('''
#ifndef {{jinjaModelName|upper}}_H
#define {{jinjaModelName|upper}}_H

#include "ns3/application.h"
#include "ns3/traced-callback.h"
#include "ns3/nstime.h"
#include "ns3/average.h"
#include "ns3/simulator.h"
#include <map>
#include "{{jinjaModelName}}-PacketFactory.h"
#include "ns3/{{jinjaModelName}}Grammar.h"

namespace ns3 {

class Socket;

/**
 * \\ingroup applications
 * \\defgroup {{jinjaModelName}} {{jinjaModelName}}
 */

/**
 * \\ingroup {{jinjaModelName}}
 * \\brief {{jinjaTodo}}
 *
 * Note: {{jinjaTodo}}
 */
class {{jinjaModelName}} : public Application
{
public:
  /**
   * \\brief Get the type ID.
   * \\return the object TypeId
   */
  static TypeId GetTypeId (void);

  /**
   * create a {{jinjaTodo}}
   */
  {{jinjaModelName}} ();
  virtual ~{{jinjaModelName}} ();

private:

  // inherited from Application base class.
  virtual void StartApplication (void);
  virtual void StopApplication (void);
  virtual void DoDispose (void);
  /**
   * \\brief Return the application ID in the node.
   * \\returns the application id
   */
  uint32_t GetApplicationId (void) const;
  /**
   * \\brief Receive an {{todo}}
   * \\param socket the receiving socket
   *
   * This function is called by lower layers through a callback.
   */
  void Receive (Ptr<Socket> socket);
  /**
   * \\brief {{jinjaTodo}}
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
  StateMachine *sm;
  /// will instantiate communication if true
  bool m_instantiator;
  /// id associated with this model instance
  uint32_t m_id;
};

} // namespace ns3

#endif /* {{jinjaModelName|upper}}_H */
''')
	ofile = open(filename, 'w')
	ofile.write(hFile.render(jinjaPacketTypes=mid, jinjaModelName=modelName, jinjaFieldNames=myFields, todo='TODO', defaultDataType='char')) #'UNKNOWN_DataType'))
	#print hFile.render(jinjaPacketTypes=mid, jinjaModelName=modelName, jinjaFieldNames=myFields, todo='TODO', defaultDataType='char') #'UNKNOWN_DataType')

def calcStrOr(smaller, smallerNumBytes, larger, largerNumBytes):
	numBytesDiff = largerNumBytes-smallerNumBytes
	largerBase16 = int(larger,16)
	smallerBase16 = int(smaller,16) << (8*numBytesDiff)
	 
	return (hex(largerBase16 | smallerBase16))[2:]

def main():
	ids = soup.find_all('mtype',{'id':True})
	outputPath = modelName+"/"+modelName+"model/"
	answer = []
	for mid in ids:
		answer.append(mid['id'])
	generateFile(outputPath+modelName+".h",answer)

if __name__ == "__main__":
	main()
