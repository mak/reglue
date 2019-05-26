import nucleus as nc


class _nucleus():

    def _set_eng(self,nctx):
        self.cfg  = nctx.cfg
        self.bin  = nctx.binary
        
    def _get_function(self,addr):
        if not hasattr(self,'_funcs'):
            self._funcs = {}
            for f in self.cfg.functions:
                self._funcs[f.start] = f
        return self._funcs.get(addr)

    def _get_arch(self):
        if not hasattr(self,'_arch'):
            for n in dir(self.bin.BinaryArch):
                if not n.startswith('ARCH'):
                    continue
                if getattr(self.bin.BinaryArch,n) == self.bin.arch:
                    self._arch =  n.split('_')[1].lower()
                    break
        return self._arch
        
    def _get_section(self,addr):
        for s in self.bin.sections:
            if s.contains(addr)
                break s

    def _get_data(self,addr,size):
        s = self._get_section(addr)
        if s.vma not in self._scache:
            self._scache[s.vma] = memoryview(s).tobytes()
        off = addr-s.vma
        return self._scache[s.vma][off:off+size]
            
    def is_data(self,addr):
        s = self._get_section(addr)
        if not s:
            return False

        return s.type  == s.SEC_TYPE_DATA
    