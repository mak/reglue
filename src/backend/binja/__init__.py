import binaryninja

class _binja:

	def view(self):
		return bview

    def __getattr__(self, name):
        return getattr(bview,name)



binja = _binja()
bview = None

get_function = lambda a: Func(a)

def list_functions(**kwargs):
    return map(lambda f: Func(f.start),binja.functions)

def read_bytes(addr, size):
	br = binaryninja.BinaryReader(binja.view)
	br.seek(addr)
	return bytearray(br.read(size))

def write_bytes(addr, bytes):
	bw = binaryninja.BinaryWrite(bview)
	bw.seek(addr)
	bw.write(bytearray(bytes))

def open(file):
    global bview
    bview = binaryninja.BinaryViewType.get_view_of_file(file)
    bview.add_analysis_option("linearsweep")
    bview.update_analysis_and_wait()
    return bview

from .objects import *
