import binaryninja

class _binja:

    def __getattr__(self, name):
        return getattr(bapi,name)

binja = _binja()
bapi = None

def list_functions(**kwargs):
    return map(lambda f: Func(f.start),binja.functions)

def open(file):
    global bapi
    bapi = binaryninja.BinaryViewType.get_view_of_file(file)
    bapi.add_analysis_option("linearsweep")
    bapi.update_analysis_and_wait()
    return bapi

from .objects import *
