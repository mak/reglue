from reglue.common.abstract import *
from . import binja

class Edge(object):
    def __init__(self,edge,g):
        self._edge = edge
        self._g = g

    @property
    def trg(self):
        return self._g.at(self._edge.target.start)
    
    @property
    def src(self):
        return self._g.at(self._edge.source.start)

class BasicBlock(BaseBasicBlock):
    def __init__(self,id,g,bb):
        self.g  = g
        self.id = id
        self.address = bb.start
        self._bb = bb
        
    @property
    def parents(self):
        return [ self.g.at(e.source.start) for e in
                 self._bb.incoming_edges ]
    @property
    def children(self):
        return [ self.g.at(e.target.start) for e in
                 self._bb.outgoing_edges ]
class Graph(BaseGraph):

    EdgeClass = Edge
    
    def load(self,blocks):
        self._edges   = []
        for i,b in enumerate(blocks):
            for e in b.outgoing_edges:
                self._edges.append(Edge(e,self))

            bb = BasicBlock(i,self,b)
            self._bbs.append(bb)
            self._addrs_to_ids[bb.address]=i
            
class Func(BaseFunc):

    def __init__(self,ea_or_name):

        addr = ea_or_name
        if isinstance(ea_or_name,basestring):
            sym = binja.get_symbol_by_raw_name
            if not sym:
                raise Exception('no such symbol!')
            addr = sym.address

        self.func = binja.get_functions_containing(addr)[0]
        self.address = self.func.start
        
    @property
    def graph(self):
        g = Graph(self)
        g.load(self.func.basic_blocks)
        return g

    
