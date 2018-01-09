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

	ccFile = Template('''
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "{{jinjaModelName}}.h"
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

NS_LOG_COMPONENT_DEFINE ("{{jinjaModelName}}");

NS_OBJECT_ENSURE_REGISTERED ({{jinjaModelName}});

TypeId
{{jinjaModelName}}::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::{{jinjaModelName}}")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<{{jinjaModelName}}> ()
    .AddAttribute ("Remote",
                   "The address of the machine we want to send a {{jinjaModelName}} packet to.",
                   Ipv4AddressValue (),
                   MakeIpv4AddressAccessor (&{{jinjaModelName}}::m_remote),
                   MakeIpv4AddressChecker ())
    .AddAttribute ("Verbose",
                   "Produce usual output.",
                   BooleanValue (false),
                   MakeBooleanAccessor (&{{jinjaModelName}}::m_verbose),
                   MakeBooleanChecker ())
    .AddAttribute ("Interval", "Wait  interval  seconds between sending each packet.",
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&{{jinjaModelName}}::m_interval),
                   MakeTimeChecker ())
    .AddAttribute ("Size", "The number of data bytes to be sent.",
                   UintegerValue (56),
                   MakeUintegerAccessor (&{{jinjaModelName}}::m_size),
                   MakeUintegerChecker<uint32_t> (16))
    .AddAttribute ("Instantiator",
                   "Will initiate communication if true.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&{{jinjaModelName}}::m_instantiator),
                   MakeBooleanChecker ())
    .AddAttribute ("ID", "The ID associated with this model instance.",
                   UintegerValue (0),
                   MakeUintegerAccessor (&{{jinjaModelName}}::m_id),
                   MakeUintegerChecker<uint32_t> ())
    .AddTraceSource ("Rtt",
                     "The rtt calculated by the ping.",
                     MakeTraceSourceAccessor (&{{jinjaModelName}}::m_traceRtt),
                     "ns3::Time::TracedCallback");
  ;
  return tid;
}

{{jinjaModelName}}::{{jinjaModelName}} ()
  : m_interval (Seconds (1)),
    m_size ({{jinjaPacketSize}}),
    m_socket (0),
    m_seq (0),
    m_verbose (false),
    m_recv (0),
    m_instantiator (true)
{

  NS_LOG_FUNCTION (this);

}
{{jinjaModelName}}::~{{jinjaModelName}} ()
{
  NS_LOG_FUNCTION (this);
}

void
{{jinjaModelName}}::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  Application::DoDispose ();
}

uint32_t
{{jinjaModelName}}::GetApplicationId (void) const
{
  NS_LOG_FUNCTION (this);
  Ptr<Node> node = GetNode ();
  for (uint32_t i = 0; i < node->GetNApplications (); ++i)
    {
      if (node->GetApplication (i) == this)
        {
          return i;
        }
    }
  NS_ASSERT_MSG (false, "forgot to add application to node");
  return 0; // quiet compiler
}

void
{{jinjaModelName}}::Receive (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  while (m_socket->GetRxAvailable () > 0)
    {
      Address from;
      Ptr<Packet> p = m_socket->RecvFrom (0xffffffff, 0, from);
      int inferredPacketType = -1;
      NS_LOG_DEBUG ("recv " << p->GetSize () << " bytes");
      //NS_ASSERT (InetSocketAddress::IsMatchingType (from));
      //InetSocketAddress realFrom = InetSocketAddress::ConvertFrom (from);
      //NS_ASSERT (realFrom.GetPort () == 1); // protocol should be icmp.
      Ipv4Header ipv4;
      p->RemoveHeader (ipv4);
      uint32_t recvSize = p->GetSize ();
      unsigned char data[p->GetSize()];
      p->CopyData(data,p->GetSize());
      //{{todo}} need to determine which message was received
      {{jinjaModelName}}PacketType* myTypeRecv;
      for (unsigned i = 0; i< {{jinjaModelName}}PacketFactory::num_types; i++)
      {
		myTypeRecv = {{jinjaModelName}}PacketFactory::createPacketType(i);
		//cout << "NODE " << m_id << ":Testing: " << myTypeRecv->GetTypeId() << endl;
		if (myTypeRecv->isPacketType(data, p->GetSize()) == 1.0)
		{
			inferredPacketType = myTypeRecv->GetTypeId();
			//cout << "NODE " << m_id << ": confidence 1, id is: " << inferredPacketType << endl;
			break;
		}
	  }   
	  cout << endl;   
      cout << "NODE " << m_id << ": received " << recvSize << " payload bytes inferred to be packet type: " << inferredPacketType << std::endl;
      
      //Here we query the state machine
      vector<int> states = sm->getNextState(inferredPacketType);
	  
	  if (states.size() == 0)
	  {
	     cout << "NODE " << m_id << ": " << "no more states in state machine" << endl;
	  }
	  else
	  {
		cout << "NODE " << m_id << ": " <<  "potential next transitions: " << endl;
		for (unsigned i=0; i<states.size(); i++)
			cout << "NODE " << m_id << ": " << states[i] << endl;		
		cout << "NODE " << m_id << ": "<< " generating message type: " << states[0] << std::endl;
		
		{{jinjaModelName}}PacketType* myTypeSend;
		myTypeSend = {{jinjaModelName}}PacketFactory::createPacketType(states[0]);
		
		cout << "NODE " << m_id << ": "<< " sent message to: " << InetSocketAddress::ConvertFrom(from).GetIpv4() << " Message Type: " << myTypeSend->GetTypeId() << std::endl;
		socket->SendTo (myTypeSend->getPacket(), 0, from);
		
		states = sm->getNextState(myTypeSend->GetTypeId());
		cout << "NODE " << m_id << ": " <<  "potential next transitions: " << endl;
		for (unsigned i=0; i<states.size(); i++)
			cout << "NODE " << m_id << ": " << states[i] << endl;		
	  }
     }
}

void
{{jinjaModelName}}::Send ()
{
  NS_LOG_FUNCTION (this);
  //call a type constructor:

  {{jinjaModelName}}PacketType* myTypeSend;
  myTypeSend = {{jinjaModelName}}PacketFactory::createPacketType(0);
  
  m_socket->Send (myTypeSend->getPacket(), 1);
  m_next = Simulator::Schedule (m_interval, &{{jinjaModelName}}::Send, this);
  cout << "NODE " << m_id << ": {{jinjaModelName}} sent packet to " << m_remote << " MessageType: " << myTypeSend->GetTypeId() << endl;
  
  vector<int> states = sm->getNextState(0);
  if (states.size() == 0)
  {
	     cout << "NODE " << m_id << ": " << "no more states in state machine" << endl;
  }
  else
  {
	cout << "NODE " << m_id << ": "<< "potential next transitions: " << endl;
	for (unsigned i=0; i<states.size(); i++)
		cout << "NODE " << m_id << ": "<<  states[i] << endl;
  }
}

void
{{jinjaModelName}}::StartApplication (void)
{
  NS_LOG_FUNCTION (this);
    
  m_started = Simulator::Now ();
  m_socket = Socket::CreateSocket (GetNode (), TypeId::LookupByName ("ns3::Ipv4RawSocketFactory"));
  NS_ASSERT (m_socket != 0);
  m_socket->SetAttribute ("Protocol", UintegerValue (6)); // {{todo}} icmp=1, tcp=6, ipv4hop=0
  m_socket->SetRecvCallback (MakeCallback (&{{jinjaModelName}}::Receive, this));
  InetSocketAddress src = InetSocketAddress (Ipv4Address::GetAny (), 0);
  int status;
  status = m_socket->Bind (src);
  NS_ASSERT (status != -1);
  InetSocketAddress dst = InetSocketAddress (m_remote, 0);
  status = m_socket->Connect (dst);
  NS_ASSERT (status != -1);
  sm = new StateMachine(0);
  if (m_instantiator)
  {
     cout << "NODE " << m_id << ": Starting instantiator; scheduled to send packets every "<<m_interval << " seconds " << endl;
     Send ();
  }
  

}
void
{{jinjaModelName}}::StopApplication (void)
{
  NS_LOG_FUNCTION (this);
  m_next.Cancel ();
  m_socket->Close ();
}


} // namespace ns3
''')
	ofile = open(filename, 'w')
	ofile.write(ccFile.render(jinjaPacketTypes=mid, jinjaModelName=modelName, jinjaFieldNames=myFields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))
	#print ccFile.render(jinjaPacketTypes=mid, jinjaModelName=modelName, jinjaFieldNames=myFields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize)

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
	print "answer",answer
	generateFile(outputPath+modelName+".cc",answer)
	
if __name__ == "__main__":
	main()
