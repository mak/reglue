import idautils

def open(f):
    ## we are allready inside inside ida
    return True


def list_functions():
	return map(Funcf. idautils.Functions())


get_function = lambda a: Func(a)
def read_bytes(addr, size):
	return bytearray(get_bytes(addr,size))
	
def write_bytes(addr, bytes):
	for i,b in enumerate(bytes):
		patch_byte(addr + i, b)



from .objects import *

