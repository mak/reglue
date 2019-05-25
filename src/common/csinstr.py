from reglue.common.translate import translate_mnem
from reglue.common.abstract import BaseInstr

try:
    import capstone as cs
    NO_CAPSTONE = False
except ImportError:
    print('[-] NoCapstone')
    NO_CAPSTONE=True

disObj = None
def get_disasm(bits=0,arch=''):
    global disObj

    if not disObj:
        c = cs.Cs(getattr(cs,'CS_ARCH_'+arch.upper()),
                  getattr(cs,'CS_MODE_'+str(bits))
        )
        c.detail = True
        disObj = c

    return disObj

#def disasm(data,addr):
#    return get_disasm().disasm(data,addr).next()
    

class CsInstr(BaseInstr):
        
    def __init__(self,addr, hxbytes):
        size = len(hxbytes) / 2
        self.start_ea = addr
        self.end_ea   = addr+size
        self.address  = addr
        self.size     = size
        self.end_ea  = self.address + self.size
        self._instr  = self._disasm(hxbytes.decode('hex'))
    
    def _disasm(self,bytes):
        return get_disasm(self.get_bits(),self.get_arch()).disasm(bytes,self.address).next()

    @property
    def mnem(self):
        a = cs.CS_ARCH[get_disasm().arch].split('_')[-1].lower()
        m = self._instr.mnemonic.split(' ')[-1] ## strip prefixes
        return translate_mnem(m,a)

    @property
    def is_mem_write(self):
        ## dunno but this seems more sane that what cs is doing
        if self.mnem == 'cmp' and\
           self._instr.operands[0].type == cs.CS_OP_MEM:
           return False
       
        for op in self._instr.operands:
            if op.type   == cs.CS_OP_MEM and\
               op.access & cs.CS_AC_WRITE:
               return True
        return False
    
    @property
    def is_mem_read(self):
        for op in self._instr.operands:
            if op.type   == cs.CS_OP_MEM and\
               op.access & cs.CS_AC_READ:
               return True
        if self.mnem == 'call' and\
           self._instr.operands[0].type == cs.CS_OP_MEM:
           return True
        
        return False 

    @property
    def is_call(self):
        return self._instr.group(cs.CS_GRP_CALL)
    
    def __str__(self):
        return '{} {}'.format(self.mnem, self._instr.op_str)