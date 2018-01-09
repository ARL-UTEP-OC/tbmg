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
			
		#print myFields		
		hFile = Template('''
#ifndef {{jinjaModelName|upper}}_TYPE_{{jinjaPacketType}}_H
#define {{jinjaModelName|upper}}_TYPE_{{jinjaPacketType}}_H
#include "ns3/{{jinjaModelName}}-PacketType.h"
#include "ns3/application.h"
#include "ns3/traced-callback.h"
#include "ns3/nstime.h"
#include "ns3/average.h"
#include "ns3/simulator.h"
#include <map>

namespace ns3 {
/**
 * \\ingroup {{jinjaModelName}}Type{{jinjaPacketType}}
 * \\brief 
 *
 * Note: 
 */
class {{jinjaModelName}}Type{{jinjaPacketType}} : public {{jinjaModelName}}PacketType
{
public:

  int GetTypeId (void);
  //getters and setters functions (auto-generated)
  {%- for fieldName in jinjaFieldNames %}
  {%- if fieldName[2]=='1' %}
  uint8_t get_{{fieldName[1]}}();
  void set_{{fieldName[1]}}(unsigned char val);
  {%- elif fieldName[2]=='2' %}
  uint16_t get_{{fieldName[1]}}();
  void set_{{fieldName[1]}}(uint16_t val);
  {%- elif fieldName[2]=='4' %}
  uint32_t get_{{fieldName[1]}}();
  void set_{{fieldName[1]}}(uint32_t val);
  {%- elif fieldName[2]=='8' %}
  uint64_t get_{{fieldName[1]}}();
  void set_{{fieldName[1]}}(uint64_t val) ;
  {%- else %}
  unsigned char* get_{{fieldName[1]}}();
  void set_{{fieldName[1]}}(unsigned char* val);
  {%- endif %}
  {%- endfor %}

  /**
   * create a {{jinjaModelName}}Type
   */
  {{jinjaModelName}}Type{{jinjaPacketType}} (/* any input parameters, these are all optional */);
  virtual ~{{jinjaModelName}}Type{{jinjaPacketType}} ();

  float isPacketType(unsigned char* candidate, int size);

  Ptr<Packet> getPacket(void);

private:
 
    /**
   * \\brief Writes data to buffer in little-endian format.
   *
   * Least significant byte of data is at lowest buffer address
   *
   * \\param buffer the buffer to write to
   * \\param data the data to write
   */
  void Write16 (uint8_t *buffer, const uint16_t data);

  /**
   * \\brief Writes data to buffer in little-endian format.
   *
   * Least significant byte of data is at lowest buffer address
   *
   * \\param buffer the buffer to write to
   * \\param data the data to write
   */
  void Write32 (uint8_t *buffer, const uint32_t data);

    /**
   * \\brief Writes data from a little-endian formatted buffer to data.
   *
   * \\param buffer the buffer to read from
   * \\param data the read data
   */
   void Write64 (uint8_t *buffer, const uint64_t data);

  /**
   * \\brief Read data from a little-endian formatted buffer to data.
   *
   * \\param buffer the buffer to read from
   * \\param data the read data
   */
  void Read16 (const uint8_t *buffer, uint16_t &data);

  /**
   * \\brief Writes data from a little-endian formatted buffer to data.
   *
   * \\param buffer the buffer to read from
   * \\param data the read data
   */
  void Read32 (const uint8_t *buffer, uint32_t &data);

  /**
   * \\brief Writes data from a little-endian formatted buffer to data.
   *
   * \\param buffer the buffer to read from
   * \\param data the read data
   */
  void Read64 (const uint8_t *buffer, uint64_t &data);

  void DoDispose (void);
  
  //variables (auto-generated)
  int mtype;
  {%- for fieldName in jinjaFieldNames %}
  {%- if fieldName[2]=='1' %}
  unsigned char {{fieldName[1]}};
  {%- elif fieldName[2]=='2' %}
  uint16_t {{fieldName[1]}};
  {%- elif fieldName[2]=='4' %}
  uint32_t {{fieldName[1]}};
  {%- elif fieldName[2]=='8' %}
  uint64_t {{fieldName[1]}};
  {%- else %}
  unsigned char {{fieldName[1]}}[{{fieldName[2]}}];
  {%- endif %}
  {%- endfor %}
  
  Ptr<Packet> dataPacket;

};

} // namespace ns3

#endif /* {{jinjaModelName_Type|upper}}_TYPE_{{jinjaPacketType}}_H */
''')
	ofile = open(filename, 'w')
	ofile.write(hFile.render(jinjaPacketType=mid, jinjaModelName=modelName, jinjaFieldNames=myFields, todo='TODO', defaultDataType='char')) #'UNKNOWN_DataType')
	print hFile.render(jinjaPacketType=mid, jinjaModelName=modelName, jinjaFieldNames=myFields, todo='TODO', defaultDataType='char') #'UNKNOWN_DataType')

def calcStrOr(smaller, smallerNumBytes, larger, largerNumBytes):
	numBytesDiff = largerNumBytes-smallerNumBytes
	largerBase16 = int(larger,16)
	smallerBase16 = int(smaller,16) << (8*numBytesDiff)
	 
	return (hex(largerBase16 | smallerBase16))[2:]

def main():
	#print calcStrOr('80',1,'10',2)
	#exit()
	ids = soup.find_all('mtype',{'id':True})
	outputPath = modelName+"/"+modelName+"model/"
	for mid in ids:
		currType = mid['id']
		generateFile(outputPath+modelName+"-type"+currType+".h",currType)
if __name__ == "__main__":
	main()
