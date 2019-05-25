from reglue.common.abstract import *
from . import ghidra_wrapper


class Op(BaseOp):

    def __init__(self, op):
        self._op = op

    def __str__(self):
        return str(self._op).lower()

class Instr(BaseInstr):
    

    def __init__(self, a, s):
        super(Instr,self).__init__(a,s)
        self._instr = None

    @property
    def instr(self):
        if not self._instr:
            self._instr = ghidra_wrapper.get_instruction(self.addr)
        return self._instr

    @property
    def mnem(self):
        return self._instr.mnemonicString.lower()

    @property
    def operands(self):
        r = []
        for i in range(self._instr.numOperands):
            op = self._instr.getOpObjects(i)[0]
            r.append(Op(op))
        return r
    

    

class Edge(object):
    def __init__(self,edge,g):
        self._edge = edge
        self._g = g
    @property
    def trg(self):
        return self.edge.destinationAddress.unsignedOffset
    
    @property
    def src(self):
        return self.edge.sourceAddress.unsignedOffset
    

class BasicBlock(BaseBasicBlock):

    def __init__(self,id,g,bb):
        self.g  = g
        self.id = id
        self.address = bb.firstStartAddress.unsignedOffset
        self._bb = bb

    @property
    def parents(self):
        return [ self.g.at(a.unsignedOffset) for a in ghidra_wrapper.get_bb_sources(_bb) if a.flowType in ghidra_wrapper.BB_FLOWS]

    @property
    def children(self):
        return [ self.g.at(a.unsignedOffset) for a in ghidra_wrapper.get_bb_destinations(_bb) if a.flowType in ghidra_wrapper.BB_FLOWS]
    
    def __iter__(self):
        for _i in ghidra_wrapper.get_bb_instructions(self._bb):
            i  = Instr(_i.address.unsignedOffset,_i.length)
            i._instr = _i 
            yield i

class Graph(BaseGraph):

    EdgeClass = Edge


    def load(self,bbi):
        self._edges   = []
        for i, b in enumerate(bbi):
            for e in ghidra_wrapper.get_bb_destinations(b):
                if e.flowType in ghidra_wrapper.BB_FLOWS:
                    self._edges.append(Edge(e,self))

            bb = BasicBlock(i,self,b)
            self._bbs.append(bb)
            self._addrs_to_ids[bb.address]=i

class Func(BaseFunc):

    def __init__(self,ea_or_name):
        self.func = ghidra_wrapper.get_function(ea_or_name)
        self.address = self.func.entryPoint.unsignedOffset

    @property
    def graph(self):
        g = Graph(self)
        g.load(ghidra_wrapper.get_basic_blocks_containing(self.func.body))
        return g