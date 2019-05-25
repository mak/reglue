import struct
from mlib.disasm import disasm as disassemble

class Mem(object):
    TRANSL = {'byte': ('=B', 1), 'word': ('H', 2),
              'dword': ('I', 4), 'qword': ('Q', 8)}

        
    def __getattr__(self, name):
        at = False
        if name.endswith('_at'):
            at = True
            name = name.strip('_at')

        if name in Mem.TRANSL:
            f, s = Mem.TRANSL[name]
            return lambda a: struct.unpack(f,self.read(a,s))[0]
        
    def disasm(self,a,n=0):
        return disassemble(base=self.base,data=self.read(a,n),address=a)


    def is_addr(self,a):
        return self.base <= a <= self.base + self.dsize
    
