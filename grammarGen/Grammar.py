import sys
import settings as s
from os.path import join

class GrammarGen:
    
    def __init__(self, model):
        self.model = model
        self.states = []
        self.transitions = []
        
        #with open(join(s.paths['statemachine'], "labeledstatemachine.dot"), "r") as dotFile:
        with open(join(s.paths['statemachine'], "labeledtree.dot"), "r") as dotFile:
            for line in dotFile:
                if "->" in line:
                    fromState, toState = line.split("->")
                    toState, condition = toState.split("[")
                    condition = condition[condition.index('"') + 1:condition.rindex('"')]
                    transition = (fromState.strip(), toState.strip(), condition.strip())
                    self.transitions.append(transition)
                if "shape" in line:
                    nodeName, excess = line.split("[",1)
                    self.states.append(nodeName.strip())

    def getStates(self):
        code = ""
        for s in self.states:
            code += "\'" + s + "', "
        code = code[:-2]
        return code
        
    def getTransitions(self):
        code = ""
        for (f, t, c) in self.transitions:
            code += "(\'" + f + "\', \'" + t + "\', " + c + "),"
        code = code[:-1]
        return code

    def writeScapyFile(self):
        model = self.model
        outputFile = join(s.paths['scapy-grammar'], model + "Grammar.py")
        with open(outputFile, "w+") as outputFile:
            code = """\
class """ + model + """StateMachine:

    def __init__(self, start):
        self.states = [""" + self.getStates() + """]
        self.transitions = [""" + self.getTransitions() + """]
        self.current = self.states[start]
        
    def getNumStates(self):
        return len(self.states)
    
    def getNextState(self, v):
        for (f, t, c) in self.transitions:
            if self.current == f and v == c:
                self.current = t
                return self.states.index(t)
"""
            outputFile.write(code)
            

    def writeNs3File(self):
        model = self.model
        outputFile = join(s.paths['ns3-grammar'], model + "-Grammar.h")
        with open(outputFile, "w+") as outputFile:
            code = """
#ifndef """ + model + """_HELPER_H
#define """ + model + """_HELPER_H
#include <iostream>
#include <string>
#include <stdio.h>
#include <vector>

using namespace std;

namespace ns3 {

    enum stateName {"""
            i = 0
            for state in self.states:
                code += state + "=" + str(i) + ", "
                i += 1
            code = code[:-2]
                
            code += """};
    
    class """ + model + """Transition {
        int transNum;
        stateName state;
        
    public:
        void addState(stateName newState) {
            state = newState;
        }
        
        void addTransNum(int nextNum) {
            transNum = nextNum;
        }
        
        stateName getName() {
            return state;
        }
        
        int getNum() {
            return transNum;
        }
    };
    
    class """ + model + """State {
    public:
        vector<""" + model + """Transition> trans;
        void addTrans(int input,stateName stateNumber) {
            """ + model + """Transition temp;
            temp.addState(stateNumber);
            temp.addTransNum(input);
            trans.push_back(temp);
        }
    };

    class """ + model + """StateMachine {
        """ + model + """State stateArray[""" + str(len(self.states)) + """];
		unsigned currState;

    public:
        """ + model + """StateMachine(unsigned startState) {
            currState = startState;
"""
            for (f, t, c) in self.transitions:
                code += "            stateArray[" + f + "].addTrans(" + c + ", " + t + ");\n"
            
            code += """
        }

        vector<int> getNextState(int input) {
            int found = 0;
            int transitNum;
            vector<int> result;
            
            for (unsigned i = 0; i < stateArray[currState].trans.size(); i++) {
                stateName state = stateArray[currState].trans[i].getName();
                transitNum = stateArray[currState].trans[i].getNum();
                if(transitNum == input) {
                    currState = state;
                    found = 1;
                    break;
                }
            }
            
            if (found) {
                for (unsigned i = 0; i < stateArray[currState].trans.size(); i++) {
                    transitNum = stateArray[currState].trans[i].getNum();
                    result.push_back(transitNum);
                }
            }

            return result;
        }

    };
} 
#endif /* """ + model + """_HELPER_H */
"""
            outputFile.write(code)
  


if __name__ == "__main__":
    x = toPyGrammar()
    x.getNextState('node0','0')
