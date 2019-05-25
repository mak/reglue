import idautils,idaapi,idc

import ida_ua
import ida_gdl

from reglue.common.abstract import *
    

class IdaObj(object):

    _get  = None
    _from = None
    
    def __init__(self,id_or_name,obj=None):
        if not obj:
            oid = id_or_name
            if isinstance(id_or_name,basestring):
                oid = self._from(id_or_name)
            obj = self._get(oid)
            
        n = self.__class__.__name__.lower()
        setattr(self,n,obj)
        if hasattr(obj,'id'):
            self.id = obj.id


class Type(IdaObj):

    def __init__(self,ti):
        self.ti = ti
        self.extra = None
        if self.ti.is_func():
            self.extra  = idaapi.func_type_data_t()
            if not self.ti.get_func_details(self.extra):
                print "[-] can't get function's type details"
                return
            
        elif self.ti.is_struct():
            self.extra = idaapi.udt_type_data_t()
            if not self.ti.get_udt_details(self.extra):
                print "[-] can't get struct's type details"
                return
                
    def __str__(self):
        return str(self.ti)

    def serialize(self):
        ordin = self.ti.get_ordinal()
        if not ordin:
            print '[-] ..'
            return
        return idaapi.idc_get_local_type_raw(ordin)
    
    def as_c(self):
        f = idaapi.PRTYPE_DEF | idaapi.PRTYPE_MULTI | idaapi.PRTYPE_DEF
        return self.ti._print('',f)

    @staticmethod
    def load(types,fields=None,cmts=None,lib=None):
        ti = idaapi.tinfo_t()
        if not ti.deserialize(lib,types,fields,cmts):
            ti = None
        return ti
    
    @staticmethod
    def add(name,types=None,fields=None,cmts=None,flags=0,lib=None):
        ti = Type.load(types,fields,cmts,lib)
        if not ti:
            print "[-] can't load this type.."
            return
        idx = idaapi.alloc_type_ordinal(None)
        if idaapi.save_tinfo(ti,lib,idx,name,flags) != idaapi.TERR_OK:
            print "[-] can't add type `%s`" % name
            return None
        
        return Type(ti)
    
class Member(IdaObj):
    _get  = staticmethod(idaapi.get_member_by_id)
    _from = staticmethod(lambda x: idaapi.get_member_by_fullname(x).id)

    @property
    def name(self):
        return idaapi.get_member_fullname(self.id)

    @property
    def type(self):
        self.ti     = idaapi.tinfo_t()
        if not idaapi.get_member_tinfo(self.ti,self.member):
            print "[-] can't get member `%s` type" % self.name
            return
        return Type(self.ti)
                
class Struct(IdaObj):

    _get  = staticmethod(idaapi.get_struc)
    _from = staticmethod(idaapi.get_struc_id)

    @staticmethod
    def add(name,types=None,fields=None,cmts=None,flags=0,lib=None):
        t = Type.add(name,types,fields,cmts,flags,lib)
        if not idaapi.apply_tinfo(0,t.ti,0):
            print "[-] can't add struct `%s`" % name
        return Struct(name)
    
    @property
    def type(self):
        self.ti     = idaapi.tinfo_t()
        self.sti    = idaapi.udt_type_data_t()
        if idaapi.guess_tinfo(self.id,self.ti) != idaapi.GUESS_FUNC_OK:
            print "[-] can't guess `%s` type" % self.name
            return
        return Type(self.ti)

    def __getitem__(self,i):
        return Member(0,obj=self.struct.get_member(i))
    
    @property
    def members(self):
        for i in range(self.struct.memqty):
            yield Member(0,obj=self.struct.get_member(i))

    @property
    def name(self):
        return idaapi.get_struc_name(self.id)

class Op(object):
    def __init__(self,op):
        self.op = op
        self.is_mem = op.type in (idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ)

    @property
    def type(self):
        return self.op.type
        
class Instr(object):

    def __init__(self,addr,size):
        self.address  = addr
        self.start_ea = addr
        self.end_ea   = addr+size
        self.size     = size
        self.i = ida_ua.insn_t()
        self._decoded = False
        self._decode()
        
    def _decode(self):
        if not self._decoded:
            self._decoded=bool(ida_ua.decode_insn(self.i,self.start_ea))
        return self._decoded
    
    @property
    def mnem(self):
        if not self._decode():
            print "[-] can't decode instruction at %x" %self.start_ea
            return 
        return self.i.get_canon_mnem()

    @property
    def flags(self):
        if not self._decode():
            print "[-] can't decode instruction at %x" %self.start_ea
            return 
        return self.i.get_canon_feature()
    
    @property
    def operands(self):
        return map(Op,self.i.Operands)
    
    @property
    def is_call(self):
        if not self._decode():
            print "[-] can't decode instruction at %x" %self.start_ea
            return 
        return idaapi.is_call_insn(self.i)

    @property
    def is_mem_read(self):
        for i, op in enumerate(self.operands):
            if op.type == idaapi.o_void:
                continue
                
            elif op.is_mem and self.flags & 1 << (i+8):
                return True
        return False

    @property
    def is_mem_write(self):
        for i, op in enumerate(self.operands):
            if op.type == idaapi.o_void:
                continue

            elif op.is_mem and self.flags & 1 << (i+2):
                return True
        return False
            
    @property
    def data_refs(self):
        return idautils.DataRefsFrom(self.address)
    
class BasicBlock(ida_gdl.BasicBlock,BaseBasicBlock):

    def __init__(self,*args,**kwargs):
        ida_gdl.BasicBlock.__init__(self,*args,**kwargs)
        self._icashe = {}
        self.g = self._fc
        
    @property
    def bytes(self):
        s= self.end_ea-self.start_ea
        return idaapi.get_many_bytes(self.start_ea,s)        
        
    def spp_hash(self):
        pass

    def __iter__(self):
        addr = idc.next_head(self.start_ea)
        prev_a = self.start_ea

        yield Instr(prev_a,addr-prev_a)
        for a in idautils.Heads(addr):
            if a >= self.end_ea:
                break
            s = a - prev_a
            prev_a = a
            yield Instr(a,s)

    def __getitem__(self,addr):
        if addr not in self._icashe:
            for i in self:
                if i.start_ea <= addr < self.end_ea:
                    self._icashe[addr] =i
                    break
        return self._icashe[i]

    @property
    def children(self):
        return self.succs()
        
class Graph(ida_gdl.FlowChart,BaseGraph):

    def __init__(self,*args,**kwargs):
        ida_gdl.FlowChart.__init__(self,*args,**kwargs)
        BaseGraph.__init__(self,self._q.pfn)
        ## aprently ida can't build proper graph...x        
        self._build_graph()

    def _build_graph(self):
        self._parents= [ [] for _ in range(self.size)]
        BaseGraph._build_graph(self)
    
    def refresh(self):
        super(Graph,self).refresh()
        self._build_graph()
        
    
    def _getitem(self, index):
        return BasicBlock(index, self._q[index], self)

    @property
    def address(self):
        return self._q.pfn.start_ea
    
class Func(IdaObj):

    class FArg(object):
        def __init__(self,obj):
            self.argloc = obj.argloc
            self.name   = obj.name
            self.type   = Type(obj.type)
            self.comment = obj.cmt
            self.flags   = obj.flags
    
    _get  = staticmethod(idaapi.get_func)
    _from = staticmethod(idc.get_name_ea_simple)
    
    def __init__(self,ea_or_name,obj=None):
        super(Func,self).__init__(ea_or_name,obj)
        self.addr = self.func.start_ea
        self._bbcache = {}
        
    @property
    def name(self):
        return idaapi.get_func_name(self.addr)
        
    @property
    def type(self):
        self.ti   = idaapi.tinfo_t()
        if not idaapi.get_tinfo(self.ti,self.addr):
            print "[-] can't get type info for ea %x" % ea
            return
        
        return Type(self.ti)

    @property
    def graph(self):
        return Graph(self.func)
    
    @property
    def bytes(self):
        return ''.join(( bb.bytes for bb in self))

    @property
    def frame(self):
        return Struct(self.func.frame)

    @property
    def rettype(self):
        return Type(self.type.extra.rettype)

    @property
    def args(self):
        r= []
        aa = self.type.extra
        for i in range(self.type.extra.size()):
            x=aa[i]
            r.append(self.FArg(x))
        return r        
    
    def __iter__(self):
        return (bb for bb in self.graph)

    
    def __getitem__(self,addr):
        if addr not in self._bbcache:
            for bb in self:
                if bb.start_ea <= addr < bb.end_ea:
                    self._bbcache[addr] =bb
                    break
        return self._bbcache[addr]
