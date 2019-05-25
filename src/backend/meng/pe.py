import pefile
from .memory import Mem


class PE(Mem):

    def __init__(self,fpath):
        self.pe = pefile.PE(fpath)
        self.base  = self.pe.OPTIONAL_HEADER.ImageBase
        self.fpath = fpath
        self.entry = self.base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

        self.imports = {}
        self._populate_imports()

    def read(self,addr,n):
        return self.pe.get_data(addr - self.base,n)
        
    def _populate_imports(self):
        if not hasattr(self.pe,'DIRECTORY_ENTRY_IMPORT'):
            return
        
        for imp in self.pe.DIRECTORY_ENTRY_IMPORT:
            name = imp.dll.lower()
            for func in imp.imports:
                x={'dll':name,'name':func.name,
                   'addr':func.address, ## perform relocations
                   'import_data':func}
                self.imports[func.address] = x 
                self.imports[func.name] = x
                
    def is_exec(self,a):
        s = self.pe.get_section_by_rva(a-self.base)
        r = False
        if s:
            r = s.IMAGE_SCN_MEM_EXECUTE and s.IMAGE_SCN_CNT_CODE
        return r
        
    def is_addr(self,a):
        return self.base <= a < self.base + self.pe.OPTIONAL_HEADER.SizeOfImage

    def is_data(self,a):
        s = self.pe.get_section_by_rva(a-self.base)
        r = False
        if s:
            r  = s.IMAGE_SCN_MEM_READ and \
            (s.IMAGE_SCN_CNT_UNINITIALIZED_DATA or s.IMAGE_SCN_CNT_INITIALIZED_DATA)
        return r
        
    
    @staticmethod
    def check(fpath):
        f = False
        try:
            p=pefile.PE(fpath)
            f=True
        except Exception as e:
            pass
        return f

        
    
