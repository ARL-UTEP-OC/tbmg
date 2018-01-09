#!/usr/bin/python
#Creates a C++ NS-3 Model Using python
from bs4 import BeautifulSoup
from jinja2 import Template
import sys
import xml.etree.ElementTree as ET
import operator

xmlFilename = sys.argv[1]
modelName = sys.argv[2]

soup = BeautifulSoup(open(xmlFilename,'r'), 'xml')

#print soup.prettify()

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
				
				
		#print myFields		
		hFile = Template('''
//auto-generated
#ifndef {{jinjaModelName|upper}}_PACKET_TYPE_H
#define {{jinjaModelName|upper}}_PACKET_TYPE_H

#include <stdio.h>
#include "ns3/header.h"
#include "ns3/ptr.h"
#include <stdint.h>
#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/socket.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/inet-socket-address.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/application.h"
#include "ns3/traced-callback.h"
#include "ns3/nstime.h"
#include "ns3/average.h"
#include "ns3/simulator.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-address.h"

namespace ns3 {
/**
 * \ingroup {{jinjaModelName}}PacketType
 * \brief 
 *
 * Note: 
 */
class {{jinjaModelName}}PacketType
{
public:

  virtual int GetTypeId (void) = 0;
  virtual float isPacketType(unsigned char* candidate, int size) = 0;
  virtual Ptr<Packet> getPacket(void) = 0;
  
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

private:
  virtual void DoDispose (void) = 0;
  Ptr<Packet> dataPacket;

};

} // namespace ns3

#endif /* PACKET_TYPE_H */

''')
	ofile = open(filename, 'w')
	ofile.write(hFile.render(jinjaPacketType=mid, jinjaModelName=modelName, jinjaFieldNames=myFields, todo='TODO', defaultDataType='char')) #'UNKNOWN_DataType')
	#print hFile.render(jinjaPacketType=mid, jinjaModelName=modelName, jinjaFieldNames=myFields, todo='TODO', defaultDataType='char') #'UNKNOWN_DataType')

def calcStrOr(smaller, smallerNumBytes, larger, largerNumBytes):
	numBytesDiff = largerNumBytes-smallerNumBytes
	largerBase16 = int(larger,16)
	smallerBase16 = int(smaller,16) << (8*numBytesDiff)
	 
	return (hex(largerBase16 | smallerBase16))[2:]

def main():
	ids = soup.find_all('mtype',{'id':True})
	outputPath = modelName+"/"+modelName+"model/"
	for mid in ids:
		currType = mid['id']
		generateFile(outputPath+modelName+"-PacketType.h",currType)
if __name__ == "__main__":
	main()
