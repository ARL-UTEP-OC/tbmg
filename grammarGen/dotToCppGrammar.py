import sys

def dotToCppGrammar(model):
    dotfilename = model + "/" + model + "StateMachine/labeledstatemachine.dot"
    dotFile = open(dotfilename, "r")
    dir = str(model)
    statesArray = []
    transArray = []
    for line in dotFile:
        if "->" in line:
            #print "found ->"
            lname, rname = line.split("->")
            rname, tran = rname.split("[")
            tran = tran[tran.index('"') + 1:tran.rindex('"')]
            tuple = (lname, rname, tran)
            transArray.append(tuple)
            # "Node "+lname+" -> "+rname+" with "+tran
        else:
            try:
                nodeName, right = line.split("[")
                statesArray.append(nodeName)
                #print nodeName

            except ValueError:
                continue

    cppFile = open(dir+"/"+dir+"Grammar.h", "w+")
    cHeaders = """
#ifndef """+dir+"""_HELPER_H
#define """+dir+"""_HELPER_H
#include <iostream>
#include <string>
#include <stdio.h>
#include <vector>

using namespace std;\n
namespace ns3 {
"""


    cEnums = "enum stateName {"
    i = 0
    for each in statesArray:
        if i<(len(statesArray)-1):
            cEnums += each +"= "+ str(i)+", "
        else:
            cEnums += each +"= "+ str(i)
        i+= 1
    cEnums += "};"

    cHeaders += cEnums
    cppFile.write(cHeaders)

    transitionClass = """
class """+dir+"""Transition{
        int transNum;
        stateName state;
 public:
        void addState(stateName newState){
                state = newState;
                }
        void addTransNum(int nextNum){
                transNum = nextNum;
                }
        stateName getName(){
               return state;
               }
        int getNum(){
              return transNum;
              }

        };
\n
"""
    stateClass = """
class """+dir+"""State{

public:

        vector<"""+dir+"""Transition> trans;
        void addTrans(int input,stateName stateNumber){
                """+dir+"""Transition temp;
                temp.addState(stateNumber);
                temp.addTransNum(input);
                trans.push_back(temp);
                }
        };\n
"""
    body = transitionClass + stateClass
    cppFile.write(body)

    stateMachineClass = """
class """+dir+"""StateMachine{
        """+dir+"""State stateArray["""+str(len(statesArray))+"""];
		unsigned currState;

public:
        """+dir+"""StateMachine(unsigned startState){
                currState = startState;
        """

    for each in transArray:
        stateMachineClass+="stateArray["+each[0].strip()+"].addTrans("+each[2]+", "+each[1].strip()+");\n        "

    stateMachineClass+= """
                }

        vector<int> getNextState(int input){
                int found = 0;
                //printf("Input is:%i ", input);
                int transitNum;
                vector<int> result;
                //printf("Current size is: %lu", stateArray[currState].trans.size());
                for(unsigned i = 0; i< stateArray[currState].trans.size(); i++){
                        stateName state = stateArray[currState].trans[i].getName();
                        transitNum = stateArray[currState].trans[i].getNum();
                        //printf("%s%i","trans is: ",transitNum);
                        if(transitNum == input){
                                //result.push_back(transitNum);
                                currState = state;
                                //printf("CurrState changed: %i", currState);
                                //cout << "CurrState changed: "<< currState << endl;
                                found = 1;
                                break;
                        }
                }
                if(found){
                        for(unsigned i = 0; i< stateArray[currState].trans.size(); i++){
                                transitNum = stateArray[currState].trans[i].getNum();
                                result.push_back(transitNum);
                        //printf("%s%i","trans is: ",transitNum);
                        }
                        //printf("%s%i","trans is: ",transitNum);
                }
                //do nothing; the result should be size 0
                /*else{
                //if(result.size()==0){
                        result.push_back(-1);
                        //}
                        }
                */
                 return result;
                }

};
} //namespace ns3
#endif /* """+dir+"""_HELPER_H */
"""

    cppFile.write(stateMachineClass)
#printV = """
#void printV(vector<int> out){
#        if(out.size()==1){
#                printf("transition is: ");
#        }
#        else{
#                printf("transitions are: ");
#        }
#        for(unsigned i = 0; i < out.size(); i++){
#                printf("%i ",out[i]);
#        }
#        printf("\\n");
#
#}\n
#"""
#cppFile.write(printV)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "usage: packetTypeExtractory.py <config file>"
        # print "<input file>"
        # print " -a file containing field data (produced by pdmlExtractor.py)\n"
        # print "<model name>"
        # print " -a file containing field data (produced by pdmlExtractor.py)\n"
        print "This program creates two files: "
        print "packetTypeSequences.txt"
        print " -this file contains the observed packet type sequences in the input file"
        print "packetTypeMapping.xml"
        print " -this file contains the mappings from numerical packet types to the unique values used as identify a unique packet type"
        sys.exit(-1)
    dotToCppGrammar(sys.argv[1])
