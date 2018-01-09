#!/usr/bin/python
#Creates a C++ NS-3 Model Using python
from bs4 import BeautifulSoup
from jinja2 import Template
import sys
from Parser import ParsePacketData

xmlFilename = sys.argv[1]
modelName = sys.argv[2]

def main():
	templates = []
	allParsedPacketData = ParsePacketData(modelName,open(xmlFilename).read())
	
	#generates: ccFileHelper.cc
	ifilename = 'modelFileGen/ns3ModelGenerator_ccFileHelper.jnj2'
	ofilename = modelName+"/"+modelName+"model/"+modelName+"-helper.cc"
	template = Template(open(ifilename).read())
	(allTypes, currType, packetTypeUnique, totalPacketSize, fields) = allParsedPacketData[0]
	ofile = open((ofilename), 'w')
	ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))

	#generates: ccFilePacketFactory.cc
	ifilename = 'modelFileGen/ns3ModelGenerator_ccFilePacketFactory.jnj2'
	ofilename = modelName+"/"+modelName+"model/"+modelName+"-PacketFactory.cc"
	template = Template(open(ifilename).read())
	(allTypes, currType, packetTypeUnique, totalPacketSize, fields) = allParsedPacketData[0]
	ofile = open((ofilename), 'w')
	ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))

	#generates: ccFilePacketType.cc
	ifilename = 'modelFileGen/ns3ModelGenerator_ccFilePacketType.jnj2'
	ofilename = modelName+"/"+modelName+"model/"+modelName+"-PacketType.cc"
	template = Template(open(ifilename).read())
	(allTypes, currType, packetTypeUnique, totalPacketSize, fields) = allParsedPacketData[0]
	ofile = open((ofilename), 'w')
	ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))

	#generates: ccFile.cc
	ifilename = 'modelFileGen/ns3ModelGenerator_ccFile.jnj2'
	ofilename = modelName+"/"+modelName+"model/"+modelName+".cc"
	template = Template(open(ifilename).read())
	(allTypes, currType, packetTypeUnique, totalPacketSize, fields) = allParsedPacketData[0]
	ofile = open((ofilename), 'w')
	ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))

	#generates: ccFileTypes.cc
	ifilename = 'modelFileGen/ns3ModelGenerator_ccFileTypes.jnj2'

	template = Template(open(ifilename).read())
	for (allTypes, currType, packetTypeUnique, totalPacketSize, fields) in allParsedPacketData:
		ofilename = modelName+"/"+modelName+"model/"+modelName+"-type"+currType+".cc"	
		ofile = open((ofilename), 'w')
		ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))

	#generates: ccFileTypes.cc
	ifilename = 'modelFileGen/ns3ModelGenerator_ccFileTypes.jnj2'
	ofilename = modelName+"/"+modelName+"model/"+modelName+"-type"+".cc"
	template = Template(open(ifilename).read())
	(allTypes, currType, packetTypeUnique, totalPacketSize, fields) = allParsedPacketData[0]
	ofile = open((ofilename), 'w')
	ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))
	
	#generates: hFileHelper.h
	ifilename = 'modelFileGen/ns3ModelGenerator_hFileHelper.jnj2'
	ofilename = modelName+"/"+modelName+"model/"+modelName+"-helper.h"
	template = Template(open(ifilename).read())
	(allTypes, currType, packetTypeUnique, totalPacketSize, fields) = allParsedPacketData[0]
	ofile = open((ofilename), 'w')
	ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))

	#generates: hFilePacketFactory.h
	ifilename = 'modelFileGen/ns3ModelGenerator_hFilePacketFactory.jnj2'
	ofilename = modelName+"/"+modelName+"model/"+modelName+"-PacketFactory.h"
	template = Template(open(ifilename).read())
	(allTypes, currType, packetTypeUnique, totalPacketSize, fields) = allParsedPacketData[0]
	ofile = open((ofilename), 'w')
	ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))		

	#generates: hFilePacketType.h
	ifilename = 'modelFileGen/ns3ModelGenerator_hFilePacketType.jnj2'
	ofilename = modelName+"/"+modelName+"model/"+modelName+"-PacketType.h"
	template = Template(open(ifilename).read())
	(allTypes, currType, packetTypeUnique, totalPacketSize, fields) = allParsedPacketData[0]
	ofile = open((ofilename), 'w')
	ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))			

	#generates: hFile.h
	ifilename = 'modelFileGen/ns3ModelGenerator_hFile.jnj2'
	ofilename = modelName+"/"+modelName+"model/"+modelName+".h"
	template = Template(open(ifilename).read())
	(allTypes, currType, packetTypeUnique, totalPacketSize, fields) = allParsedPacketData[0]
	ofile = open((ofilename), 'w')
	ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))			

	#generates: hFileTypes.h
	ifilename = 'modelFileGen/ns3ModelGenerator_hFileTypes.jnj2'

	template = Template(open(ifilename).read())
	for (allTypes, currType, packetTypeUnique, totalPacketSize, fields) in allParsedPacketData:
		ofilename = modelName+"/"+modelName+"model/"+modelName+"-type"+currType+".h"
		ofile = open((ofilename), 'w')
		ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))

	#generates: ns3WscriptGenerator.h
	ifilename = 'modelFileGen/ns3WscriptGenerator.jnj2'
	ofilename = modelName+"/"+modelName+"model/"+"wscript"
	template = Template(open(ifilename).read())
	(allTypes, currType, packetTypeUnique, totalPacketSize, fields) = allParsedPacketData[0]
	ofile = open((ofilename), 'w')
	ofile.write(template.render(jinjaPacketTypes=allTypes, jinjaPacketType=currType, jinjaPacketTypeUnique=packetTypeUnique, jinjaModelName=modelName, jinjaFieldNames=fields, todo='TODO', defaultDataType='char', jinjaPacketSize=totalPacketSize))			
				 
if __name__ == "__main__":
	main()
