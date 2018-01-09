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

	ccTypeFile = Template('''
//This file was generated automatically, please do not edit unless you know exactly what you're doing.
#include "{{jinjaModelName}}-type{{jinjaPacketType}}.h"
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

NS_LOG_COMPONENT_DEFINE ("{{jinjaModelName}}-type{{jinjaPacketType}}");

int
{{jinjaModelName}}Type{{jinjaPacketType}}::GetTypeId (void)
{
  {{TODO}}
  return mtype;
}

//Get/Set functions (auto-generated)
{%- for fieldName in jinjaFieldNames %}
{%- if fieldName[2]=='1' %}
unsigned char 
{{jinjaModelName}}Type{{jinjaPacketType}}::get_{{fieldName[1]}}()
{
  {{TODO}}
  return {{fieldName[1]}};
}
void {{jinjaModelName}}Type{{jinjaPacketType}}::set_{{fieldName[1]}}(unsigned char val)
{
  {{TODO}}
  {{fieldName[1]}} = val;
}
{%- elif fieldName[2]=='2' %}
uint16_t
{{jinjaModelName}}Type{{jinjaPacketType}}::get_{{fieldName[1]}}()
{
  {{TODO}}
  return {{fieldName[1]}};
}
void {{jinjaModelName}}Type{{jinjaPacketType}}::set_{{fieldName[1]}}(uint16_t val)
{
  {{TODO}}
  {{fieldName[1]}} = val;
}
{%- elif fieldName[2]=='4' %}
uint32_t
{{jinjaModelName}}Type{{jinjaPacketType}}::get_{{fieldName[1]}}()
{
  {{TODO}}
  return {{fieldName[1]}};
}
void {{jinjaModelName}}Type{{jinjaPacketType}}::set_{{fieldName[1]}}(uint32_t val)
{
  {{TODO}}
  {{fieldName[1]}} = val;
}
{%- elif fieldName[2]=='8' %}
uint64_t
{{jinjaModelName}}Type{{jinjaPacketType}}::get_{{fieldName[1]}}()
{
  {{TODO}}
  return {{fieldName[1]}};
}
void {{jinjaModelName}}Type{{jinjaPacketType}}::set_{{fieldName[1]}}(uint64_t val)
{
  {{TODO}}
  {{fieldName[1]}} = val;
}
{%- else %}
unsigned char* {{jinjaModelName}}Type{{jinjaPacketType}}::get_{{fieldName[1]}}()
{
  {{TODO}}
  return {{fieldName[1]}};
}
void {{jinjaModelName}}Type{{jinjaPacketType}}::set_{{fieldName[1]}}(unsigned char* val)
{
  {{TODO}}
  memcpy({{fieldName[1]}},val,{{fieldName[2]}});
}
{%- endif %}
{%- endfor %}

/**
 * create a {{jinjaModelName}}Type{{jinjaPacketType}}
 */

{{jinjaModelName}}Type{{jinjaPacketType}}::{{jinjaModelName}}Type{{jinjaPacketType}} ()//(/* any input parameters, these are all optional */);
{
  //set default values
  {%- for fieldName in jinjaFieldNames %}
  {%- if fieldName[2]=='1' or fieldName[2] == '2' or fieldName[2] == '4' or fieldName[2] == '8' %}
  {{fieldName[1]}} = {{fieldName[4].split(';')[0]}};//ENTROPY: {{fieldName[3]}} {%- if fieldName[3]|float >0 %} , see xml for other values {%- endif %}
  {%- else %}
  unsigned char {{fieldName[1]}}Tmp[{{fieldName[2]}}] = { {{fieldName[4].split(';')[0]|replace(" ",",")}} };//ENTROPY: {{fieldName[3]}}, see xml for other values
  memcpy({{fieldName[1]}},{{fieldName[1]}}Tmp,{{fieldName[2]}});
  {%- endif %}
  {%- endfor %}
  mtype = {{jinjaPacketType}};
}
{{jinjaModelName}}Type{{jinjaPacketType}}::~{{jinjaModelName}}Type{{jinjaPacketType}} ()
{
  {{TODO}}
}
  
float
{{jinjaModelName}}Type{{jinjaPacketType}}::isPacketType(unsigned char *candidate, int size)
{
  //HERE!
  //here we try to build the type of packet and depending on the results we return a confidence value
  float confidence = 1.0;

  {% set count = 0 %}
  {%- for fieldName in jinjaFieldNames %}
  {%- if fieldName[2]=='1' %}
  //read 1 byte and store it into the variable:
  memcpy(&{{fieldName[1]}},&candidate[{{count}}], {{fieldName[2]}});
  //std::cout << "{{fieldName[1]}}: " << (unsigned){{fieldName[1]}} << std::endl;
  //std::cout << " 0x" << std::hex << (int){{fieldName[1]}} << std::endl;
  {%- elif fieldName[2]=='2' %}
  //read 2 byte and store it into the variable:
  Read16(&candidate[{{count}}], {{fieldName[1]}});
  //std::cout << "{{fieldName[1]}}: " << (unsigned){{fieldName[1]}} << std::endl;
  //std::cout << " 0x" << std::hex << (int){{fieldName[1]}} << std::endl;
  {%- elif fieldName[2]=='4' %}
  //read 4 byte and store it into the variable:
  Read32(&candidate[{{count}}], {{fieldName[1]}});
  //std::cout << "{{fieldName[1]}}: " << (unsigned){{fieldName[1]}} << std::endl;
  //std::cout << " 0x" << std::hex << (int){{fieldName[1]}} << std::endl;
  {%- elif fieldName[2]=='8' %}
  //read 8 byte and store it into the variable:
  Read64(&candidate[{{count}}], {{fieldName[1]}});
  //std::cout << "{{fieldName[1]}}: " << (unsigned){{fieldName[1]}} << std::endl;
  //std::cout << " 0x" << std::hex << (int){{fieldName[1]}} << std::endl;
  {%- else %}
  //read byte and store into the variable:
  memcpy(&{{fieldName[1]}},&candidate[{{count}}], {{fieldName[2]}});
  //std::cout << "{{fieldName[1]}}: ";
  //for ( int i =0; i<{{fieldName[2]}}; i++)
	//std::cout << " 0x" << std::hex << (int){{fieldName[1]}}[i];
  //std::cout << std::endl;
  {%- endif %}
  {%- set count = count + fieldName[2]|int %}
  //printf("%#010x\\n",{{fieldName[1]}});
  {%- endfor %}
  
  //std::cout << "Original:" << std::endl;
  //for ( int i =0; i<size; i++)
  //   std::cout << " 0x" << std::hex << (int)candidate[i];
  //std::cout << std::endl;
  //{{todo}}
  //std::cout << "confidence: " << confidence << std::endl;
  ////this should be a memcmp
  if ({{jinjaPacketTypeUnique[0][0]}} == {{jinjaPacketTypeUnique[0][1]}})
    confidence = 1.0;
  else confidence = 0.0;

  return confidence;
}

// Writes data to buffer in little-endian format; least significant byte
// of data is at lowest buffer address
void
{{jinjaModelName}}Type{{jinjaPacketType}}::Write32 (uint8_t *buffer, const uint32_t data)
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
{{jinjaModelName}}Type{{jinjaPacketType}}::Write16 (uint8_t *buffer, const uint16_t data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  buffer[0] = (data >> 8) & 0xff;
  buffer[1] = (data >> 0) & 0xff;
}

// Writes data to buffer in little-endian format; least significant byte
// of data is at lowest buffer address
void
{{jinjaModelName}}Type{{jinjaPacketType}}::Write64 (uint8_t *buffer, uint64_t data)
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
{{jinjaModelName}}Type{{jinjaPacketType}}::Read16 (const uint8_t *buffer, uint16_t &data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  //data = (buffer[1] << 8) + buffer[0];
  data = (buffer[0] << 8) + buffer[1];
}

// Writes data from a little-endian formatted buffer to data
void
{{jinjaModelName}}Type{{jinjaPacketType}}::Read32 (const uint8_t *buffer, uint32_t &data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  data = (buffer[0] << 24) + (buffer[1] << 16) + (buffer[2] << 8) + buffer[3];
}

// Writes data from a little-endian formatted buffer to data
void
{{jinjaModelName}}Type{{jinjaPacketType}}::Read64 (const uint8_t *buffer, uint64_t &data)
{
  //still not sure why we need the casts to (uint64_t) to rid the compile-time warning
  NS_LOG_FUNCTION (this << buffer << data);
  data = ((uint64_t)buffer[0] << 56) + ((uint64_t)buffer[1] << 48) + ((uint64_t)buffer[2] << 40) + ((uint64_t)buffer[3] << 32) + ((uint64_t)buffer[4] << 24) + ((uint64_t)buffer[5] << 16) + ((uint64_t)buffer[6] << 8) + (uint64_t)buffer[7];
}

Ptr<Packet> {{jinjaModelName}}Type{{jinjaPacketType}}::getPacket()
{
  uint8_t sendData[{{ jinjaPacketSize }}];
  {% set count = 0 %}
  {%- for fieldName in jinjaFieldNames %}
  {%- if fieldName[2]=='1' %}
  memcpy(&sendData[{{count}}],&{{fieldName[1]}}, sizeof({{fieldName[1]}}));
  {%- elif fieldName[2]=='2' %}
  Write16(&sendData[{{count}}],{{fieldName[1]}});
  {%- elif fieldName[2]=='4' %}
  Write32(&sendData[{{count}}],{{fieldName[1]}});
  {%- elif fieldName[2]=='8' %}
  Write64(&sendData[{{count}}],{{fieldName[1]}});
  {%- else %}
  memcpy(&sendData[{{count}}],{{fieldName[1]}},{{fieldName[2]}});
  {%- endif %}
  {%- set count = count + fieldName[2]|int %}
  {%- endfor %}
//  std::cout << "testing packet similarity" << std::endl;
//  isPacketType(sendData, 48);

  dataPacket = Create<Packet> ((uint8_t *) sendData, {{jinjaPacketSize}});
  return dataPacket;
}

void {{jinjaModelName}}Type{{jinjaPacketType}}::DoDispose (void)
{

}

} // namespace ns3

''')

	ofile = open(filename, 'w')
	ofile.write(ccTypeFile.render(jinjaPacketType=mid, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=myFields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize)) #'UNKNOWN_DataType')
	#print ccTypeFile.render(jinjaPacketType=mid, jinjaModelName=modelName, jinjaFieldNames=myFields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize) #'UNKNOWN_DataType')

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
		generateFile(outputPath+modelName+"-type"+currType+".cc",currType)
if __name__ == "__main__":
	main()
