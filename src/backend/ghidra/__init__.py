from .wrapper import _ghidra


ghidra_wrapper = _ghidra()


def list_functions(**kwargs):
    return map(lambda f: Func(f.getEntryPoint()),ghidra_wrapper.fmgr.getFunctions(True))


def get_function(name_or_ea):
    return Func(name_or_ea)

def open(filename):
    ## same as ida?
    return ghidra_wrapper.init()

    
from .objects import *
