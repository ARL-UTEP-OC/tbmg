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
//auto-generated
#include "{{jinjaModelName}}-PacketType.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("{{jinjaModelName}}-PacketType");

// Writes data to buffer in little-endian format; least significant byte
// of data is at lowest buffer address
void
{{jinjaModelName}}PacketType::Write32 (uint8_t *buffer, const uint32_t data)
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
{{jinjaModelName}}PacketType::Write16 (uint8_t *buffer, const uint16_t data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  buffer[0] = (data >> 8) & 0xff;
  buffer[1] = (data >> 0) & 0xff;
}

// Writes data to buffer in little-endian format; least significant byte
// of data is at lowest buffer address
void
{{jinjaModelName}}PacketType::Write64 (uint8_t *buffer, uint64_t data)
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
{{jinjaModelName}}PacketType::Read16 (const uint8_t *buffer, uint16_t &data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  //data = (buffer[1] << 8) + buffer[0];
  data = (buffer[0] << 8) + buffer[1];
}

// Writes data from a little-endian formatted buffer to data
void
{{jinjaModelName}}PacketType::Read32 (const uint8_t *buffer, uint32_t &data)
{
  NS_LOG_FUNCTION (this << buffer << data);
  data = (buffer[0] << 24) + (buffer[1] << 16) + (buffer[2] << 8) + buffer[3];
}

// Writes data from a little-endian formatted buffer to data
void
{{jinjaModelName}}PacketType::Read64 (const uint8_t *buffer, uint64_t &data)
{
  //still not sure why we need the casts to (uint64_t) to rid the compile-time warning
  NS_LOG_FUNCTION (this << buffer << data);
  data = ((uint64_t)buffer[0] << 56) + ((uint64_t)buffer[1] << 48) + ((uint64_t)buffer[2] << 40) + ((uint64_t)buffer[3] << 32) + ((uint64_t)buffer[4] << 24) + ((uint64_t)buffer[5] << 16) + ((uint64_t)buffer[6] << 8) + (uint64_t)buffer[7];
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
		generateFile(outputPath+modelName+"-PacketType.cc",currType)
if __name__ == "__main__":
	main()
