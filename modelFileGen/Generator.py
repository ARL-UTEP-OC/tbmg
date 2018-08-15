#!/usr/bin/python
# Creates a C++ NS-3 Model Using python
import sys
import settings as s
from os import getcwd
from os.path import join
from bs4 import BeautifulSoup
from Parser import ParsePacketData
from jinja2 import Environment, FileSystemLoader


def generateModels(modelName, transLayer, routingData):
    '''Generate the source code for the NS3 and Scapy models.'''
    
    # Templates used to generate a single file
    # (output file, template)
    ns3_single = [
        (join(s.paths['ns3-model'], modelName + "-helper.cc"),        join(s.paths['ns3-templates'], "ccFileHelper.jnj2")),
        (join(s.paths['ns3-model'], modelName + "-PacketFactory.cc"), join(s.paths['ns3-templates'], "ccFilePacketFactory.jnj2")),
        (join(s.paths['ns3-model'], modelName + "-PacketType.cc"),    join(s.paths['ns3-templates'], "ccFilePacketType.jnj2")),
        (join(s.paths['ns3-model'], modelName + "-type.cc"),          join(s.paths['ns3-templates'], "ccFileTypes.jnj2")),
        (join(s.paths['ns3-model'], modelName + "-helper.h"),         join(s.paths['ns3-templates'], "hFileHelper.jnj2")),
        (join(s.paths['ns3-model'], modelName + "-PacketFactory.h"),  join(s.paths['ns3-templates'], "hFilePacketFactory.jnj2")),
        (join(s.paths['ns3-model'], modelName + "-PacketType.h"),     join(s.paths['ns3-templates'], "hFilePacketType.jnj2")),
        (join(s.paths['ns3-model'], modelName + ".h"),                join(s.paths['ns3-templates'], "hFile.jnj2")),
        (join(s.paths['ns3-model'], "wscript"),                       join(s.paths['ns3-templates'], "wscript.jnj2")),
        (join(s.paths['ns3-scenario'], modelName + ".cc"),            join(s.paths['ns3-templates'], "scenario.jnj2")),
        (join(s.paths['ns3-scenario'], modelName + "_hil.cc"),        join(s.paths['ns3-templates'], "hil.jnj2"))
        ]
        
    scapy_single = [
        (join(s.paths['scapy-model'], modelName + "Client.py"), join(s.paths['scapy-templates'], "client.jnj2"))
        ]

    # Templates used to generate multiple files
    # (output file, extension, template)
    ns3_multiple = [
        (join(s.paths['ns3-model'], modelName + "-type"), ".cc", join(s.paths['ns3-templates'], "ccFileTypes.jnj2")),
        (join(s.paths['ns3-model'], modelName + "-type"), ".h", join(s.paths['ns3-templates'], "hFileTypes.jnj2"))
        ]
        
    scapy_multiple = [
        (join(s.paths['scapy-model'], modelName + "Type"), ".py", join(s.paths['scapy-templates'], "pyPacketType.jnj2"))
        ]

    # Check for transport layer
    if transLayer is not None:
        ns3_single.append((join(s.paths['ns3-model'], modelName + ".cc"), join(s.paths['ns3-templates'], transLayer, "ccFile.jnj2")))
    else:
        transLayer = ""

    # Set file loader for templates
    env = Environment(
        loader=FileSystemLoader("/")
    )

    # Parse packet data
    xmlFilename = join(s.paths['model'], "modelStandardizedXMLFile.xml")
    packetData = ParsePacketData(modelName, open(xmlFilename).read())
    
    import json
    print "\n\n",json.dumps(packetData,indent=4),"\n\n"
    
    # Generate files
    produced = []
    for (output, template) in (ns3_single + scapy_single):
        template = env.get_template(template)
        _renderFromTemplate(modelName, template, output, packetData[0], routingData)
        produced.append(output)
    
    for (output, ext, template) in (ns3_multiple + scapy_multiple):
        template = env.get_template(template)

        # Iterate for each type
        for data in packetData:
            outputFile = output + str(data[2][0][1]) + ext
            _renderFromTemplate(modelName, template, outputFile, data, routingData)
            produced.append(outputFile)
    
    return produced


def _renderFromTemplate(model, template, output, (allTypes, currType, packetTypeUnique, totalPacketSize, fields, layerData), routingData):
    with open(output, 'w') as out:
        out.write(template.render(
                    jinjaPacketTypes=allTypes,
                    jinjaPacketType=currType,
                    jinjaPacketTypeUnique=packetTypeUnique,
                    jinjaModelName=model,
                    jinjaFieldNames=fields,
                    jinjaLayerData=layerData,
                    jinjaRoutingData=routingData,
                    todo='TODO',
                    defaultDataType='char',
                    jinjaPacketSize=totalPacketSize
                    )
        )

if __name__ == "__main__":
    generateModels(sys.argv[1],None)
