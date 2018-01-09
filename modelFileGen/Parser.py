#!/usr/bin/python
# Creates a C++ NS-3 Model Using python
from bs4 import BeautifulSoup
import sys

def extractFieldData(modelName, mid, soup_modelStandardizedXML):
    soup = soup_modelStandardizedXML
    myFields = []
    packetTypeUnique = []
    layerData = {}
    totalPacketSize = 0
    currFieldPos = 0
    for myType in soup.find_all('mtype', id=mid):
        var = myType['typeuniq'].split('=')[0].replace(".", "_").encode('ascii').strip()
        val = int(myType['typeuniq'].split('=')[1].replace(".", "_").encode('ascii'),16)
        packetTypeUnique.append((var, val))
        
        items = myType['nodeuniq'].split(';')
        for i in items:
            var, val = i.split('=')
            var = var.encode('ascii').strip()
            val = val.encode('ascii').strip()
            layerData[var] = val
        
        currPacketSize = 0
        
        for myField in myType.find_all('mfield'):
            # only include the field if its byte location has not been specified by another field:
            if (len(myField.msize.contents) > 0 
            and myField.msize.contents[0].split(';')[0] != '0' 
            and len(myField.mvalue.contents) > 0 
            and len(myField.mvalue.contents) > 0):
                
                # fix up the mname field:
                mname = myField.mname.contents[0].split(';')[0].replace("(", "").replace(")", "").replace(" ", "_").replace(".", "_")
                
                # fix up the vocab field to work with C++ (hex bytes)
                mvalue = ""
                mvalueItem = myField.mvalue.contents[0].split(';')[0]
                if len(mvalueItem)%2 != 0:
                    mvalueItem = "0" + mvalueItem
                    
                if mvalueItem.strip() != ';' and mvalueItem.strip() != '':
                    msize = int(myField.msize.contents[0].split(';')[0])
                    if msize == 2 or msize == 4 or msize == 8:
                        mvalue = "0x" + mvalueItem
                    else:
                        #print "HERE!!!!!!!",mvalueItem
                        mvalueItem = mvalueItem.decode("hex")
                        mvalue = ''.join(["0x%02X " % ord(x) for x in mvalueItem]).strip()
                if int(myField.mpos.contents[0].split(';')[0]) == currFieldPos or len(myFields) == 0:
                    # print 'NEW: adding new',myField.mname.contents[0].split(';')[0].replace("(","").replace(")","").replace(" ","_").replace(".","_")
                    myFields.append((myType['id'], mname, myField.msize.contents[0].split(';')[0],
                                     myField.mentropy.contents[0].split(';')[0], mvalue,
                                     myField.mpos.contents[0].split(';')[0]))
                    currFieldPos = int(myField.mpos.contents[0].split(';')[0]) + int(
                        myField.msize.contents[0].split(';')[0])
                    totalPacketSize += int(myField.msize.contents[0].split(';')[0])

                elif int(myField.mpos.contents[0].split(';')[0]) < currFieldPos:
                    # print 'LESS: found pos less than existing: ',myField.mname.contents[0].split(';')[0].replace("(","").replace(")","").replace(" ","_").replace(".","_")
                    # print "TEST: ", myField.msize.contents[0].split(';')[0],'>',int(myFields[-1][2])
                    if int(myField.msize.contents[0].split(';')[0]) > int(myFields[-1][2]):
                        # print 'RES: replacing because curr is sample pos and bigger than previous'
                        # print 'before:',myFields[-1]
                        rpId = myType['id']
                        rpName = mname.split(';')[0]
                        rpSize = myField.msize.contents[0].split(';')[0]
                        rpEnt = myField.mentropy.contents[0].split(';')[0]
                        rpVal = calcStrOr(myFields[-1][4], int(myFields[-1][2]),
                                          myField.mvalue.contents[0].split(';')[0], int(rpSize))
                        rpVal = "0x" + str(rpVal)
                        rpPos = myField.mpos.contents[0].split(';')[0]
                        totalPacketSize += (int(myField.msize.contents[0].split(';')[0]) - int(myFields[-1][2]))
                        myFields[-1] = (rpId, rpName, rpSize, rpEnt, rpVal, rpPos)
                        currFieldPos = int(rpPos) + int(rpSize)
                        # print 'after:',myFields[-1]
                    else:
                        {}  # print 'RES: not bigger'
                else:
                    {}  # print 'IGNORED:',myField.mname.contents[0].split(';')[0].replace("(","").replace(")","").replace(" ","_").replace(".","_")'
    return (packetTypeUnique, totalPacketSize, myFields, layerData)


def calcStrOr(smaller, smallerNumBytes, larger, largerNumBytes):
    numBytesDiff = largerNumBytes - smallerNumBytes
    largerBase16 = int(larger, 16)
    smallerBase16 = int(smaller, 16) << (8 * numBytesDiff)
    return (hex(largerBase16 | smallerBase16))[2:]


def ParsePacketData(modelName, modelStandardizedXML):

    soup = BeautifulSoup(modelStandardizedXML, 'xml')
    allTypes = soup.find_all('mtype', {'id': True})

    mid = []
    answer = []
    for currTypePacket in allTypes:
        mid.append(currTypePacket['id'])

    for currTypePacket in allTypes:
        currType = str(currTypePacket['id'])
        (packetTypeUnique, totalPacketSize, fields, layerData) = extractFieldData(modelName, currType, soup)
        answer.append((mid, currType, packetTypeUnique, totalPacketSize, fields, layerData))
    return answer

if __name__ == "__main__":
    ParsePacketData(sys.argv[1], sys.argv[2])
