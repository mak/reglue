class robject(object):
    def __repr__(self):
        return "%s at 0x%x" % (str(self),id(self))

    
        

class BaseType(object):
    pass
#class BbMember(object):
class BaseStruct(object):
    pass
class BaseOp(object):
    pass

class BaseInstr(robject):
    def __init__(self,addr,size) :
        self.start_ea = addr
        self.end_ea   = addr+size
        self.address  = addr
        self.size     = size

    @property
    def mnem(self):
        raise NotImplementedError

    @property
    def operands(self):
        raise NotImplementedError
    

    def __str__(self):
        return "{} {} @ {:x}".format(self.mnem, ', '.join(map(str,self.operands)),self.address)

class BaseBasicBlock(robject):
    
    @property
    def parents(self):
        return (self.g[i] for i in self.g._parents[self.id])
    
    def __hash__(self):
        return self.id + self._fc.adress
    
    def __eq__(self,other):
        if other.__class__ == self.__class__:
            if other.id == self.id:
                return True
        else:
            return False

    def __getitem__(self,addr):
        if addr not in self._icashe:
            for i in self:
                if i.start_ea <= addr < self.end_ea:
                    self._icashe[addr] =i
                    break
        return self._icashe[i]
        
    def __str__(self):
        return "BB<%d>@0x%x" % (self.id,self.address)
    
class BaseFunc(robject):
    def __iter__(self):
        return (bb for bb in self.graph)

    def __str__(self):
        n = getattr(self,"name","sub_%x" % self.address)
        return "%s@0x%x" % (n,self.address)

    
class BaseEdge(robject):
    def __init__(self,src,trg,graph):
        self.src= src
        self.trg= trg
        self.g= graph

    def __str__(self):
        return "Edge(0x%x -> 0x%x)" % (self.src.address,self.trg.address)
    
Edge = BaseEdge

class BaseGraph(object):

    EdgeClass = BaseEdge
    
    def __init__(self,func):
        self.f = func        
        self._bbs = []
        self._addrs_to_ids = {}
        
    def at(self,addr):
        return self._bbs[self._addrs_to_ids[addr]]
        
    def _build_graph(self):
        self._edges=[]
        for b in self:
            for bns in b.children:
                self._parents[bns.id].append(b.id)
                self._edges.append(self.EdgeClass(b,bns,self))
            
    def __getitem__(self, index):
        return self._bbs[index]

    def __iter__(self):
        for b in self._bbs:
            yield b
    
    @property
    def edges(self):
        return self._edges

    @property
    def nodes(self):
        return self

    @property
    def adress(self):
        return self.f.address

    @property
    def size(self):
        return len(self._bbs)
