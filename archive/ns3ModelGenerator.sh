#!/bin/bash
# ------------------------------------------------------------------
#	-Jaime Acosta
#	-Caesar Zapata
#          
#	This script will generate an ns3 scenario file and a ping model (including helper files)
#
# 2015-08-11:
# 	Script created and tested with the following parameters: 
#	./ns3ModelGenerator.sh  samples/captures/ping_capture_with_eth_fcs.pcap icmp summerping"
#
# ------------------------------------------------------------------

SUBJECT=some-unique-id
VERSION=0.1.0
USAGE="Usage: ./ns3ModelGenerator.sh <pcap file> <protocol> <model name>"

# --- Option processing --------------------------------------------
if [ $# == 0 ] ; then
    echo $USAGE
    exit 1;
fi

while getopts ":vh" optname
  do
    case "$optname" in
      "v")
        echo "Version $VERSION"
        exit 0;
        ;;
      "h")
        echo $USAGE
        exit 0;
        ;;
      "?")
        echo "Unknown option $OPTARG"
        exit 0;
        ;;
      *)
        echo "Unknown error while processing options"
        exit 0;
        ;;
    esac
  done

shift $(($OPTIND - 1))

if [ $# -ne 9 ] ; then
    echo $USAGE
    exit 1;
fi

CONFIG_FILE=$1
PCAPFILE=$2
PROTOCOL=$3
MODELNAME=$4
KEYWORD=$5
MULTI=$6
REMOTE=$7
LOCAL=$8
GATE=$9

echo $KEYWORD
#Convert the model name to all lowercase (an ns3 thing)
MODELNAME=${MODELNAME,,}

#we only want one instance of this script running at one time
LOCK_FILE=/tmp/${SUBJECT}.lock
if [ -f "$LOCK_FILE" ]; then
echo "Script is already running"
exit
fi
trap "rm -f $LOCK_FILE" EXIT
touch $LOCK_FILE 

# -----------------------------------------------------------------
#only uncomment the following lines the first time you execute this script
if [ ! -d ./ns-allinone-3.23]
then
tar jxvf ns-allinone-3.23.tar.bz2
fi
#------------------------------------------------------------------

##########################Packet Annotation and Sequencing#####################
#First extract fields and flows from the pcap file (first converted to pdml with tshark)
#input: pcap file -- manually filtered to contain 1 flow
#output: packets.xml - each packet in xml format (filtered on $PROTOCOL)
#output: fields.txt - packet data (in non-xml format)
#output: scenarioStandardizedXMLFile.xml -- node specific informaiton used for generating ns-3 scenario file (specific to icmp)
mkdir $MODELNAME
#python pdmlExtractor/pdmlExtractor.py $PCAPFILE $PROTOCOL $MODELNAME $REMOTE $LOCAL $GATE
python pdmlExtractor/pdmlExtractor.py $CONFIG_FILE

#Get the types of messages and produce the sequence for prospex (will create a state machine)
#input: packets.xml
#output: packetsTypes.xml -- unique packets mapped to a number
#output: packetTypeSequences.txt -- the sequence of packets (numbers) as taken from the pcap file
#python packetTypeExtractor/packetTypeExtractor.py $MODELNAME/packets.xml $MODELNAME $KEYWORD
python packetTypeExtractor/packetTypeExtractor.py $CONFIG_FILE

##########################State Machine Generation#############################      (CZ)  Left off here 12/13 
#Create the model Standardized file
#input: packetsTypes.xml 
#output: modelStandardizedXMLFile.xml--this file contains field vocabularies for each packet type
python vocabularyExtractor/fieldVocab.py $CONFIG_FILE $MODELNAME/packetsTypes.xml $MODELNAME

mkdir $MODELNAME/$MODELNAME"sm"/
cp $MODELNAME/packetTypeSequences.txt $MODELNAME/$MODELNAME"sm"/sessions.txt

tar zxvf prospex.tgz
tar zxvf exbar.tgz
cd exbar
./autogen.sh
make
cp src/exbar ../prospex
cd ../prospex

#input: sessions.txt
#output: labeledstatemachine.dot -- a figure showing the state machine for the flow
python prospex.py ../$MODELNAME/$MODELNAME"sm"
cd ../

#########################ns3 new model setup###################################

cd ns-allinone-3.23/ns-3.23/src/
./create-module.py $MODELNAME
cd ../../../


##########################Automatic Model Generation#############################

#inputs: labeledstatemachine.dot
#output: $MODELNAMEGrammar.h -- the c++ version of the statemachine
python grammarGen/dotToCppGrammar.py $MODELNAME/$MODELNAME"sm"/labeledstatemachine.dot $MODELNAME
cp $MODELNAME/$MODELNAME"Grammar.h" ns-allinone-3.23/ns-3.23/src/"$MODELNAME"/model/

#Create directories for holding the genearted output files
mkdir $MODELNAME/$MODELNAME"model"
mkdir $MODELNAME/$MODELNAME"Scenario/"

python modelFileGen/Generator.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
#Create the model files and place them in the directory created by ./create-module.py
#input: modelStandardizedXMLFile.xml
#output: model .cc and .h files into a folder called $MODELNAME/$MODELNAME"model"/"<filename>; finally copy to ns3 directory
##python modelFileGen/ns3ModelGenerator_hFile.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
##python modelFileGen/ns3ModelGenerator_ccFile.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
cp $MODELNAME/$MODELNAME"model"/$MODELNAME.* ns-allinone-3.23/ns-3.23/src/"$MODELNAME"/model/

#Create the helper files and place them in the directory created by ./create-module.py
#input: modelStandardizedXMLFile.xml
#output: helper .cc and .h files into a folder called $MODELNAME/$MODELNAME"model"/"<filename>; finally copy to ns3 directory
##python modelFileGen/ns3ModelGenerator_hFileHelper.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
##python modelFileGen/ns3ModelGenerator_ccFileHelper.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
cp $MODELNAME/$MODELNAME"model"/*helper* ns-allinone-3.23/ns-3.23/src/"$MODELNAME"/helper/

#Create the packet type super class files and place them in the directory created by ./create-module.py
#input: modelStandardizedXMLFile.xml
#output: packet type super class .cc and .h files into a folder called $MODELNAME/$MODELNAME"model"/"<filename>; finally copy to ns3 directory
##python modelFileGen/ns3ModelGenerator_hFilePacketType.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
##python modelFileGen/ns3ModelGenerator_ccFilePacketType.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
cp $MODELNAME/$MODELNAME"model"/*PacketType* ns-allinone-3.23/ns-3.23/src/"$MODELNAME"/model/

#Create the type files (one for each packet type found in pcap) and place them in the directory created by ./create-module.py
#input: modelStandardizedXMLFile.xml
#output: packet type .cc and .h files into a folder called $MODELNAME/$MODELNAME"model"/"<filename>; finally copy to ns3 directory
##python modelFileGen/ns3ModelGenerator_hFileTypes.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
##python modelFileGen/ns3ModelGenerator_ccFileTypes.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
cp $MODELNAME/$MODELNAME"model"/*type*  ns-allinone-3.23/ns-3.23/src/"$MODELNAME"/model/

#Create the Packet Factory files and place them in the directory created by ./create-module.py
#input: modelStandardizedXMLFile.xml
#output: packet factory .cc and .h files into a folder called $MODELNAME/$MODELNAME"model"/"<filename>; finally copy to ns3 directory
##python modelFileGen/ns3ModelGenerator_hFilePacketFactory.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
##python modelFileGen/ns3ModelGenerator_ccFilePacketFactory.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
cp $MODELNAME/$MODELNAME"model"/*PacketFactory* ns-allinone-3.23/ns-3.23/src/"$MODELNAME"/model/

#now copy a new wscript file that contains references to the needed code files
##python modelFileGen/ns3WscriptGenerator.py $MODELNAME/modelStandardizedXMLFile.xml $MODELNAME
cp $MODELNAME/$MODELNAME"model"/wscript ns-allinone-3.23/ns-3.23/src/"$MODELNAME"/wscript

##########################Automatic NS3 Model Generation#######################
#create the scenario generator:
#input: #MODELNAME
#output: scenario .cc into a folder called $MODELNAME/$MODELNAME.cc
##python scenarioGen/xmlToNs3Scenario.py "$MODELNAME"/modelStandardizedXMLFile.xml $MODELNAME
cp $MODELNAME/$MODELNAME"Scenario/"$MODELNAME".cc" ns-allinone-3.23/ns-3.23/scratch

##########################Simulation Execution#################################
#run the simulation

cd ns-allinone-3.23/ns-3.23/
./waf configure
make
./waf --run scratch/$MODELNAME

#copy the resulting pcap files
cd ../../
mkdir pcapCaptures$MODELNAME
cp ns-allinone-3.23/ns-3.23/*.pcap pcapCaptures$MODELNAME
