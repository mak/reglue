from reglue.backend.abstract import *
from reglue.backend import translate_mnem

from . import nucleus


class Func(BaseFunc):

    def __init__(self,addr):
        self.func    = nucleus._get_function(addr)
        self.address = self.func.start

    @property
    def graph(self):
        g = Graph(self)
        g.load(self.func.BBs)
        return g



def remove_edge(bb,e):
        
    b1 = e.dst
    bb.insns  += b1.insns
    bb.end     = b1.end
    bb.targets = b1.targets

    b1.targets   = []
    b1.ancestors = []
    
    del e
    del b1
    
call_edge = ['call','fallthrough']


class Edge(object):
    def __init__(self,edge,g):
        self._edge = edge
        self._g = g

    @property
    def trg(self):
        return self._g.at(self._edge.dst.start)
    
    @property
    def src(self):
        return self._g.at(self._edge.src.start)


class Graph(BaseGraph):

    def load(self,blocks):
        self._edges  = []
        skip = set()
        for b in blocks:
            if sorted(map(lambda e: e.type2str(),b.targets)) == call_edge:
                e = filter(lambda e: e.type2str() == 'fallthrough',b.targets)[0]
                anc = e.dst.ancestors
                if len(anc) == 1 and anc[0].src == b:
                    skip.add(e.dst.start)
                    remove_edge(b,e)
                else:
                    print anc,b
                    raise Exception('impossible')

        for i,b in enumerate(blocks):
            if b.start in skip:
                continue
            if not b.ancestors and not b.targets:
                ## we removed them already
                continue

            for e in b.targets:
                self._edges.append(Edge(e,self))
                
            bb = BasicBlock(i,self,b)
            self._bbs.append(bb)
            self._addrs_to_ids[bb.address] = i
            
            
                
        
class BasicBlock(BaseBasicBlock):
    def __init__(self,id,g,bb):
        self.g  = g
        self.id = id
        self.address = bb.start
        self._bb = bb

    @property
    def parents(self):
        return [ self.g.at(e.src.start) for e in
                 self._bb.ancestors ]

    @property
    def children(self):
        return [ self.g.at(e.dst.start) for e in
                 self._bb.targets ]

    def __iter__(self):
        for i in self._bb.insns:
            ii = Instr(i.start,i.size)
            ii.load(i)
            yield ii
    
class Instr(BaseInstr):

    def load(self,instr):
        self._instr = instr

    @property
    def mnem(self):
        m = self._instr.mnem.split(' ')[-1] ## strip prefixes
        return translate_mnem(m,nucleus._get_arch())


    @property
    def data_refs(self):
        dst = None
        for op in self.operands:
            if op.is_imm and nucleus.is_data(op.val):
                dst = op.val
                break
            if op.is_mem and nucleus.is_data(op.val):
                dst = op.val
                break
        
    def __str__(self):
        return "0x%x: %s %s" % (self.address,self.mnem,self._instr.op_str)
