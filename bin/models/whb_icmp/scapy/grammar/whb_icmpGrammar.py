class whb_icmpStateMachine:

    def __init__(self, start):
        self.states = ['node0', 'node1', 'node2', 'node3', 'node4', 'node5', 'node6', 'node7', 'node8', 'node9', 'node10', 'node11', 'node12', 'node13', 'node14', 'node15', 'node16', 'node17', 'node18', 'node19']
        self.transitions = [('node0', 'node1', 0),('node1', 'node2', 1),('node2', 'node3', 0),('node3', 'node4', 1),('node4', 'node5', 0),('node5', 'node6', 1),('node6', 'node7', 0),('node7', 'node8', 1),('node8', 'node9', 0),('node9', 'node10', 1),('node10', 'node11', 0),('node11', 'node12', 1),('node12', 'node13', 0),('node13', 'node14', 1),('node14', 'node15', 0),('node15', 'node16', 1),('node16', 'node17', 0),('node17', 'node18', 1),('node18', 'node19', 0)]
        self.current = self.states[start]
        
    def getNumStates(self):
        return len(self.states)
    
    def getNextState(self, v):
        for (f, t, c) in self.transitions:
            if self.current == f and v == c:
                self.current = t
                return self.states.index(t)
