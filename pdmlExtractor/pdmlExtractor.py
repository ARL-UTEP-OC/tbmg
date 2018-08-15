#!/usr/bin/python
from bs4 import BeautifulSoup
import lxml.etree as ET
import sys
import subprocess
import settings as s
from os.path import join
import shlex

from jinja2 import Template

def extractPDML(pcapFilename, protoName, modelName, fields, luaScript):

    jinjaXSLInputFilename = join(s.paths['templates'], "pdmlExtractor.jnj2")
    jinjaXSLOutputFilename = join(s.paths['model'], "pdmlExtractor.xslt")
    outputPacketsFilename = join(s.paths['model'], "packets.xml")
    
    import json
    print "\n\n",json.dumps(fields,indent=4),"\n\n"
    
    # Convert PCAP to PDML
    outputPDMLFilename = pcapFilename + ".pdml"
    cmd = "/usr/bin/tshark -r " + pcapFilename + " -T pdml"
    if luaScript is not None and luaScript.strip() != "":
        dissectorFilename = join(s.paths['dissectors'], luaScript)
        cmd = cmd + " -X lua_script:" + dissectorFilename
    cmd = cmd + " > " + outputPDMLFilename
    print "\n\n","*"*60,"\n| convert PCAP to PDML\n",cmd,"\n","*"*60,"\n\n"
    subprocess.call(cmd, shell=True)

    # Generate model XSL
    with open(jinjaXSLInputFilename) as f:
        template = Template(f.read())
        xslOutput = template.render(jinjaProtoName=protoName, jinjaFields=fields)
    with open(jinjaXSLOutputFilename, 'w') as o:
        o.write(xslOutput)
            

    #####use the created xslt to transform pdml####
    dom = ET.parse(outputPDMLFilename)
    xslt = ET.parse(jinjaXSLOutputFilename)
    transform = ET.XSLT(xslt)
    newdom = transform(dom)
    #print(ET.tostring(newdom, pretty_print=True))

    #####replace empty names with variable names
    packetsXML = BeautifulSoup(ET.tostring(newdom), "xml")

    for packetXML in packetsXML.find_all("packet"):
        numNameMissing = 0
        for fieldXML in packetXML.find_all("field"):
            # check if the current field is a type specifier
            # -----------------Adding a flag to see if the actual type was found in the packet
            if not fieldXML.mname.string:
                fieldXML.mname.string = protoName + ".mname.unk." + str(numNameMissing)
                numNameMissing = numNameMissing + 1

    with open(outputPacketsFilename, "w") as o:
        # Terribly inefficient, but only way to keep the output human readable and bs-readable without having to trim all strings
        o.write(ET.tostring(ET.fromstring(str(packetsXML)), pretty_print=True))

    return {
        'jinjaXSLOutputFilename':jinjaXSLOutputFilename
        ,'outputPacketsFilename':outputPacketsFilename
        ,'outputPDMLFilename':outputPDMLFilename
    }

if __name__ == "__main__":
    extractPDML(sys.argv[1])
