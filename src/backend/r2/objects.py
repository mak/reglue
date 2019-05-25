from reglue.common.abstract import *
from reglue.common import CsInstr

from . import  r2
import capstone as cs


disObj   = None

def get_disasm():
    global disObj
    global cpu
    global cpu_name
    
    if not disObj:
        c = cs.Cs(getattr(cs,'CS_ARCH_'+arch.upper()),
                  getattr(cs,'CS_MODE_'+str(bits))
        )
        c.detail = True
        disObj = c
#        cpu = getattr(__import__('capstone.'+arch),arch)
#        cpu_name = cpu.__name__.split('.')[-1].upper() 
        
    return disObj

    
class Graph(BaseGraph):
    def load(self,blocks):
        self._parents = []
        for i,b in enumerate(blocks):
            self._parents.append([])
            bb = BasicBlock(i,self,0)
            bb.load(b)
            self._bbs.append(bb)
            self._addrs_to_ids[bb.address]=i
     
class Func(BaseFunc):

    def __init__(self,addr):
        self.address = addr

    @property
    def graph(self):
        blocks = r2.get_basicblocks(self.address)
        g = Graph(self)
        g.load(blocks)
        g._build_graph()
        return g

    @property
    def props(self):
        return r2.get_address_info(self.address).split()
    
    @property
    def is_exec(self):
        return 'exec' in self.props

    @property
    def cyclomatic_complexity(self):
        return self._data['cc']
    cc = cyclomatic_complexity
    
    def load(self,data):
        self._data = data
        pass

class Instr(CsInstr):

    def load(self,data):
        self.address = self.start_ea = data['offset']
        self.size    = data['size']
        self.end_ea  = self.address + self.size
        self._instr  = disasm(data['bytes'].decode('hex'),self.address)
        self._data   = data

    def get_arch(self):
        return r2.cmd('iIj')['arch']

    def get_bits(self):
        return r2.cmd('iIj')['bits']

    def reload(self):
        idata = r2.cmd('pdj','1','@0x%x'%self.address)
        self.load(idata)

    @property
    def is_call(self):
        return self._data['type'] == 'ucall'
    
    def __str__(self):
        return self._data['disasm']

    @property
    def data_refs(self):
        refs = r2.cmd('axfj','@0x%x'%self.address)
        return iter(filter(lambda r: r['type'] == 'data',refs))
        
class BasicBlock(BaseBasicBlock):

    def __init__(self,id,g,addr):
        self.g  = g
        self.id = id
        self.address = addr
        self.start_ea = addr
        
    def load(self,dict):
        self._succs = [ dict[t] for t in ('jump','fail') if t in dict]
        self.address = dict['addr']
        self.start_ea = self.address
        self.end_ea   = self.address + dict['addr']
        self._data = dict
         
    @property
    def children(self):
        return (self.g.at(a) for a in self._succs)


    def _manual_iter(self):
        size = self._data['size']
        addr = self.address
        while size:
            idata = r2.cmd('pdj','1','@0x%x'%addr)[0]
            ins = Instr(0,0)
            ins.load(idata)
            yield ins
            size -= idata['size']
            addr += idata['size']

    def _regular_iter(self):
        instructions = r2.cmd('pdj',str(self._data['ninstr']),
                              '@0x%x'%self.address)
        for i,idata in enumerate(instructions):
            ins = Instr(0,0)
            ins.load(idata)
        
            yield ins

            
    def __iter__(self):
        if not self._data['ninstr'] and self._data['size']:
            return self._manual_iter()
        
        return self._regular_iter()
