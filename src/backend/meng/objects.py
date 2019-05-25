from reglue.common.abstract import *
from . import eng


class BasicBlock(BaseBasicBlock):
    def __init__(self,id,g,bb):
        self.g  = g
        self.id = id
        self.address = bb.begin
        self._bb = bb

    @property
    def parents(self):
        return [ self.g.at(a) for a in self._bb.frm]

    @property
    def children(self):
        return [ self.g.at(a) for a in self._bb.to ]
    
class Graph(BaseGraph):
    def load(self,blocks):
        self._parents = []
        for i,b in enumerate(blocks):
            self._parents.append([])
            bb = BasicBlock(i,self,b)
            self._bbs.append(bb)
            self._addrs_to_ids[bb.address]=i
        

class Func(BaseFunc):

    def __init__(self,addr):
        self.addr = addr
        self.bbs  = eng.get_reachable_blocks(addr)

    @property
    def graph(self):
        g = Graph(self)
        g.load(self.bbs)
        g._build_graph()
        return g

    
