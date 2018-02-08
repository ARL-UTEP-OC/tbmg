import subprocess
import shlex
import sys
import os

from pdmlExtractor.pdmlExtractor import extractPDML
from packetTypeExtractor.packetTypeExtractor import extractPacketType
from vocabularyExtractor.fieldVocab import extractVocab
from grammarGen.Grammar import GrammarGen
from modelFileGen.Generator import generateModels


import settings as s
from os.path import join, exists, isfile
from distutils.dir_util import mkpath
from utils import *

    
# Archive Decompression
#---------------------------------------------------------------------------------------------------
def unpackArchives():
    #if (not exists("ns-allinone-3.26")):
    #    creationCheck("ns-allinone-3.26.tar.bz2")
    #    pid = subprocess.call(['tar', 'jxvf', 'ns-allinone-3.26.tar.bz2'])
    
    if (not exists("prospex")):
        creationCheck("prospex.tgz")
        res = subprocess.call(['tar', 'xvf', 'prospex.tgz'])

    if (not exists("exbar")):
        creationCheck("exbar.tgz")
        res = subprocess.call(['tar', 'zxvf', 'exbar.tgz'])


# Packet Annotation and Sequencing
#---------------------------------------------------------------------------------------------------
def extractPackets(pcapFilename, protoname, model, keyword, fields, dissector):
    # Extract fields and flows from the pcap file 
    #
    # Ensures the generation of:
    #   packets.xml - each packet in xml format (filtered on $PROTOCOL)
    #   fields.txt - packet data (in non-xml format)
    #   modelStandardizedXMLFile.xml - node specific information used for generating ns-3 scenario file (specific to icmp)
    extractPDML(pcapFilename, protoname, model, fields, dissector)
    creationCheck(join(s.paths['model'], "pdmlExtractor.xslt"))
    #creationCheck(join(s.paths['ns3-scenario'], model + "_hil.cc"))
    creationCheck(join(s.paths['model'], "packets.xml"))

    # Extract packet types and produce the sequence for prospex (will create a state machine)
    # 
    # Ensures the generation of:
    #   packetsTypes.xml - unique packets mapped to a number
    #   packetTypeSequences.txt - the sequence of packets (numbers) as taken from the pcap file
    extractPacketType(model, keyword)
    creationCheck(join(s.paths['model'], "packetTypeSequences.txt"))
    creationCheck(join(s.paths['model'], "packetsTypes.xml"))

# State Machine Generation
#---------------------------------------------------------------------------------------------------
def buildStateMachine(model):
    # Create the model Standardized file
    # 
    # Ensures the generation of:
    #   modelStandardizedXMLFile.xml - this file contains field vocabularies for each packet type
    extractVocab(model)
    creationCheck(join(s.paths['model'], "modelStandardizedXMLFile.xml"))

    src = join(s.paths['model'], "packetTypeSequences.txt")
    dst = join(s.paths['statemachine'], "sessions.txt")
    copy(src, dst)
    
    pid = subprocess.Popen(['make', 'distclean'], cwd=s.paths['exbar'])
    pid.wait()
    
    pid = subprocess.Popen([join(s.paths['exbar'], 'autogen.sh')], cwd=s.paths['exbar'])
    pid.wait()

    pid = subprocess.Popen(['make'], cwd=s.paths['exbar'])
    pid.wait()

    src = join(s.paths['exbar'], "src", "exbar")
    copy(src, s.paths['prospex'])
    
    script = join(s.paths['prospex'], "prospex.py")
    pid = subprocess.Popen(['python', script, s.paths['statemachine']], cwd=s.paths['prospex'])
    pid.wait()

# Setup new NS3 model
#---------------------------------------------------------------------------------------------------
def setupNS3Model(model):
    script = join(s.paths['ns3'], "src", "create-module.py")
    pid = subprocess.Popen(['python', script, model], cwd=s.paths['prospex'])
    pid.wait()


# Convert the state machine into usable grammar
#---------------------------------------------------------------------------------------------------
def buildNS3Grammar(model):
    gen = GrammarGen(model)
    gen.writeNs3File()
    
    src = join(s.paths['ns3-grammar'], model + "-Grammar.h")
    creationCheck(src)
    
    dst = join(s.paths['ns3'], "src", model, "model")
    copy(src, dst)
    
def buildScapyGrammar(model):
    gen = GrammarGen(model)
    gen.writeScapyFile()
    
    src = join(s.paths['scapy-grammar'], model + "Grammar.py")
    creationCheck(src)

# Generate models
#---------------------------------------------------------------------------------------------------
def buildModels(model, transLayer, routingData):
    produced = generateModels(model, transLayer, routingData)
#    for f in produced:
#        creationCheck(f)
#
#    # Copy generated model into NS3 source
#    ns3Path = join(s.paths['ns3'], "src", model)
#    modelFiles = [f for f in os.listdir(s.paths['ns3-model']) if isfile(join(s.paths['ns3-model'], f))]
#    
#    for f in modelFiles:
#        src = join(s.paths['ns3-model'], f)
#        if "helper" in f:
#            copy(src, join(ns3Path, "helper"))
#        elif "wscript" in f:
#            copy(src, ns3Path)
#        else:
#            copy(src, join(ns3Path, "model"))
#
#    # Copy generated scenario into NS3 scratch
#    src = join(s.paths['ns3-scenario'], model + ".cc")
#    copy(src, s.paths['scratch'])


# Simulation Execution
#---------------------------------------------------------------------------------------------------
def runSimulation(model, hil):
    pid = subprocess.Popen([join(s.paths['ns3'], "waf"), "configure"], cwd=s.paths['ns3'])
    pid.wait()

    pid = subprocess.Popen(['make'], cwd=s.paths['ns3'])
    pid.wait()

    # Run either the HIL or the sim-only scenario, depending on input file configuration
    if hil == "True":
        pid = subprocess.Popen([join(s.paths['ns3'], "waf"), '--run', join("scratch", model + "_hil")], cwd=s.paths['ns3'])
    else:
        pid = subprocess.Popen([join(s.paths['ns3'], "waf"), '--run', join("scratch", model)], cwd=s.paths['ns3'])
    pid.wait()


# Save Results from Simulation
#---------------------------------------------------------------------------------------------------
def saveNS3Results(model):
    pcaps = [f for f in os.listdir(s.paths['ns3']) if isfile(join(s.paths['ns3'], f))]
    for f in pcaps:
        if ".pcap" in f:
            src = join(s.paths['ns3'], f)
            dst = join(s.paths['ns3-captures'])
            copy(src, dst)


#def saveScapyResults(model):

def buildModelStructure():
    for name, path in s.paths.items():
        mkpath(path)

def main(xmlConfig):
    c = s.parseXMLConfig(xmlConfig)
    
    unpackArchives()
    if (exists(c["modelName"])):
        #result = raw_input("Existing " + config.modelName + " model will be replaced. Continue? (y/n) ")
        #if (result == "n"):
            #sys.exit()
        subprocess.call(['rm', '-r', c["modelName"]])
        
    mkpath(c["modelName"])
    s.loadSettings(c["modelName"])
    
    buildModelStructure()
    extractPackets(c["pcapFilename"], c["protoName"], c["modelName"], c["keyword"], c["fields"], c["dissectorFilename"])
    buildStateMachine(c["modelName"])#uncomment
#    setupNS3Model(c["modelName"])
#    buildNS3Grammar(c["modelName"])
    buildScapyGrammar(c["modelName"])
    buildModels(c["modelName"], c["transLayer"], {"remote": c["remote"], "local": c["local"], "gateway": c["gateway"]})
#    runSimulation(c["modelName"], c["hil"])
#    saveNS3Results(c["modelName"])
    
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: python modelGenerator.py <configuration file>"
        sys.exit()
    main(sys.argv[1])
