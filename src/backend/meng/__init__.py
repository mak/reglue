from mlib.disasm.eng import E

from .memory import Mem
from .pe import PE


class _eng:
    def __getattr__(self, name):
        return getattr(eobj,name)

eng = _eng()
eobj = None

def get_loader(f):
    for kl in Mem.__subclasses__():
        if kl.check(f):
            return kl(f)
    return Mem

def list_functions(**kwargs):
    return map(lambda f: Func(f),eng._funcs)

def open(f):
    global eobj
    kl = get_loader(f)
    eobj = E(kl)
    eobj.run()
    
    return eng
    


from .objects import *
