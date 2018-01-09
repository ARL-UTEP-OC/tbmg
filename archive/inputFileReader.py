import subprocess
import shlex
import sys
import os
from FileIO.ConfigFile import ConfigFileReader
from pdmlExtractor.pdmlExtractor import extractPDML
from packetTypeExtractor.packetTypeExtractor import extractPacketType
from vocabularyExtractor.fieldVocab import extractVocab
from grammarGen.dotToCppGrammar import dotToCppGrammar
from modelFileGen.Generator import generateModels

configData = {}
if len(sys.argv) < 2:
    print"""
    Usage: python inputFileReader.py <configuration file>
"""
    exit()

filename = sys.argv[1]

configData = ConfigFileReader.getDataFromFile(filename)
#subprocess.call(["./ns3ModelGenerator.sh", filename, configData["pcapFilename"], configData["protoName"], configData["modelName"], configData["keyword"], configData["multi"], configData["remote"], configData["local"], configData["gateway"]])

# -----------------------------------------------------------------
#only uncomment the following lines the first time you execute this script
#pid = subprocess.Popen(shlex.split("tar jxvf ns-allinone-3.23.tar.bz2"))
#pid.wait()
#------------------------------------------------------------------

##########################Packet Annotation and Sequencing#####################
#First extract fields and flows from the pcap file (first converted to pdml with tshark)
#input: pcap file -- manually filtered to contain 1 flow
#output: packets.xml - each packet in xml format (filtered on $PROTOCOL)
#output: fields.txt - packet data (in non-xml format)
#output: scenarioStandardizedXMLFile.xml -- node specific informaiton used for generating ns-3 scenario file (specific to icmp)
pid = subprocess.Popen(shlex.split("mkdir "+configData["modelName"]))
pid.wait()

pid = subprocess.Popen(shlex.split("mkdir "+configData["modelName"]+"/" + configData["modelName"]+"Scenario/"))
pid.wait()

extractPDML(filename)

#Get the types of messages and produce the sequence for prospex (will create a state machine)
#input: packets.xml
#output: packetsTypes.xml -- unique packets mapped to a number
#output: packetTypeSequences.txt -- the sequence of packets (numbers) as taken from the pcap file
#python packetTypeExtractor/packetTypeExtractor.py $MODELNAME/packets.xml $MODELNAME $KEYWORD
extractPacketType(filename)

##########################State Machine Generation#############################      (CZ)  Left off here 12/13
#Create the model Standardized file
#input: packetsTypes.xml
#output: modelStandardizedXMLFile.xml--this file contains field vocabularies for each packet type
extractVocab(filename)

pid = subprocess.Popen(shlex.split("mkdir "+configData["modelName"]+"/" + configData["modelName"]+"sm/"))
pid.wait()

pid = subprocess.Popen(shlex.split("cp "+configData["modelName"]+"/packetTypeSequences.txt " + configData["modelName"]+"/" + configData["modelName"]+"sm/sessions.txt"))
pid.wait()

pid = subprocess.Popen(shlex.split("tar zxvf prospex.tgz"))
pid.wait()

pid = subprocess.Popen(shlex.split("tar zxvf exbar.tgz"))
pid.wait()

pid = subprocess.Popen(os.getcwd() + "/exbar/autogen.sh",
                       cwd=os.getcwd() + "/exbar/")
pid.wait()

pid = subprocess.Popen("make",
                       cwd=os.getcwd() + "/exbar/")
pid.wait()

pid = subprocess.Popen(shlex.split("cp exbar/src/exbar prospex/"))
pid.wait()

#input: sessions.txt
#output: labeledstatemachine.dot -- a figure showing the state machine for the flow
cmd = "python " + os.getcwd() + "/prospex/prospex.py ../" + configData["modelName"]+"/" + configData["modelName"]+"sm/"
pid = subprocess.Popen(shlex.split(cmd),
                       cwd=os.getcwd() + "/prospex/")
pid.wait()

#########################ns3 new model setup###################################
cmd = os.getcwd() + "/ns-allinone-3.23/ns-3.23/src/create-module.py " + configData["modelName"]
pid = subprocess.Popen(shlex.split(cmd),
                       cwd=os.getcwd() + "/prospex/")
pid.wait()

##########################Automatic Model Generation#############################
#inputs: labeledstatemachine.dot
#output: $MODELNAMEGrammar.h -- the c++ version of the statemachine
dotToCppGrammar(filename)

cmd = "cp " + configData["modelName"]+"/" + configData["modelName"]+"Grammar.h " + "ns-allinone-3.23/ns-3.23/src/"+configData["modelName"] + "/model/"
pid = subprocess.Popen(shlex.split(cmd))
pid.wait()

#Create directories for holding the genearted output files
pid = subprocess.Popen(shlex.split("mkdir "+configData["modelName"]+"/" + configData["modelName"]+"model/"))
pid.wait()

generateModels(filename)

#Create the model files and place them in the directory created by ./create-module.py
#input: modelStandardizedXMLFile.xml
#output: model .cc and .h files into a folder called $MODELNAME/$MODELNAME"model"/"<filename>; finally copy to ns3 directory
##python modelFileGen/ns3ModelGenerator_hFile.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
##python modelFileGen/ns3ModelGenerator_ccFile.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
cmd="cp " + configData["modelName"]+"/"+configData["modelName"]+"model"+"/"+configData["modelName"]+".* "+ "ns-allinone-3.23/ns-3.23/src/"+configData["modelName"]+"/model/"
pid = subprocess.Popen(cmd, shell=True)
pid.wait()

#Create the helper files and place them in the directory created by ./create-module.py
#input: modelStandardizedXMLFile.xml
#output: helper .cc and .h files into a folder called $MODELNAME/$MODELNAME"model"/"<filename>; finally copy to ns3 directory
cmd="cp " + configData["modelName"]+"/"+configData["modelName"]+"model"+"/"+"*helper* "+ "ns-allinone-3.23/ns-3.23/src/"+configData["modelName"]+"/helper/"
pid = subprocess.Popen(cmd, shell=True)
pid.wait()

#Create the packet type super class files and place them in the directory created by ./create-module.py
#input: modelStandardizedXMLFile.xml
#output: packet type super class .cc and .h files into a folder called $MODELNAME/$MODELNAME"model"/"<filename>; finally copy to ns3 directory
cmd="cp " + configData["modelName"]+"/"+configData["modelName"]+"model"+"/"+"*PacketType* "+ "ns-allinone-3.23/ns-3.23/src/"+configData["modelName"]+"/model/"
pid = subprocess.Popen(cmd, shell=True)
pid.wait()

#Create the type files (one for each packet type found in pcap) and place them in the directory created by ./create-module.py
#input: modelStandardizedXMLFile.xml
#output: packet type .cc and .h files into a folder called $MODELNAME/$MODELNAME"model"/"<filename>; finally copy to ns3 directory
cmd="cp " + configData["modelName"]+"/"+configData["modelName"]+"model"+"/"+"*type* "+ "ns-allinone-3.23/ns-3.23/src/"+configData["modelName"]+"/model/"
pid = subprocess.Popen(cmd, shell=True)
pid.wait()

#Create the Packet Factory files and place them in the directory created by ./create-module.py
#input: modelStandardizedXMLFile.xml
#output: packet factory .cc and .h files into a folder called $MODELNAME/$MODELNAME"model"/"<filename>; finally copy to ns3 directory
cmd="cp " + configData["modelName"]+"/"+configData["modelName"]+"model"+"/"+"*PacketFactory* "+ "ns-allinone-3.23/ns-3.23/src/"+configData["modelName"]+"/model/"
pid = subprocess.Popen(cmd, shell=True)
pid.wait()

#now copy a new wscript file that contains references to the needed code files
##python modelFileGen/ns3WscriptGenerator.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
cmd="cp " + configData["modelName"]+"/"+configData["modelName"]+"model"+"/"+"wscript "+ "ns-allinone-3.23/ns-3.23/src/"+configData["modelName"]+"/wscript"
pid = subprocess.Popen(cmd, shell=True)
pid.wait()

##########################Automatic NS3 Model Generation#######################
#create the scenario generator:
#input: #MODELNAME
#output: scenario .cc into a folder called $MODELNAME/$MODELNAME.cc
cmd="cp " + configData["modelName"]+"/"+configData["modelName"]+"Scenario"+"/"+configData["modelName"]+".cc "+ "ns-allinone-3.23/ns-3.23/scratch/"
pid = subprocess.Popen(cmd, shell=True)
pid.wait()

print "HERE!!!!!!!!!!!",cmd
cmd="cp " + configData["modelName"]+"/"+configData["modelName"]+"Scenario"+"/"+configData["modelName"]+"_hil.cc "+ "ns-allinone-3.23/ns-3.23/scratch/"
pid = subprocess.Popen(cmd, shell=True)
pid.wait()

##########################Simulation Execution#################################
#run the simulation
pid = subprocess.Popen(shlex.split(os.getcwd()+"/ns-allinone-3.23/ns-3.23/waf configure"),
                       cwd=os.getcwd() + "/ns-allinone-3.23/ns-3.23/")
pid.wait()

pid = subprocess.Popen(shlex.split("make"),
                       cwd=os.getcwd() + "/ns-allinone-3.23/ns-3.23/")
pid.wait()

#Run either the HIL or the sim-only scenario, depending on input file configuration
if configData["hil"] == "True":
    pid = subprocess.Popen(shlex.split(os.getcwd()+"/ns-allinone-3.23/ns-3.23/waf --run scratch/"+configData["modelName"]+"_hil"),
                           cwd=os.getcwd() + "/ns-allinone-3.23/ns-3.23/")
else:
    pid = subprocess.Popen(shlex.split(os.getcwd() + "/ns-allinone-3.23/ns-3.23/waf --run scratch/" + configData["modelName"]),
                           cwd=os.getcwd() + "/ns-allinone-3.23/ns-3.23/")

pid.wait()

#copy the resulting pcap files
pid = subprocess.Popen(shlex.split("mkdir pcapCaptures"+configData["modelName"]))
pid.wait()

cmd = "cp ns-allinone-3.23/ns-3.23/*.pcap pcapCaptures"+configData["modelName"]
pid = subprocess.Popen(cmd, shell=True)
pid.wait()
