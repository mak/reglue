from .wrapper import _ghidra


ghidra_wrapper = _ghidra()


def list_functions(**kwargs):
    return map(lambda f: Func(f.getEntryPoint()),ghidra_wrapper.fmgr.getFunctions(True))


get_function = lambda a: Func(a)
read_bytes  = ghidra_wrapper.read_bytes
write_bytes = ghidra_wrapper.write_bytes

def open(filename,**kwargs):
    ## same as ida?
    cp = kwargs.get('cp')
    return ghidra_wrapper.init(cp)

    
from .objects import *
