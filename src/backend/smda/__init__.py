import os
from collections import OrderedDict
import pkg_resources

from smda.utility.FileLoader import FileLoader
from smda.Disassembler import Disassembler

class AttrDict(OrderedDict):
    def __getattr__(self,name):
        if name in self:
            return self[name]
        return super(AttrDict,self).__getattr__(name)



class Config:
	API_COLLECTION_FILES = {
		'win_xp': pkg_resources.resource_filename('smda','data/apiscout_winxp_prof_sp3.json'),
		'win_7' : pkg_resources.resource_filename('smda','data/apiscout_win7_prof-n_sp1.json')
 	}
	TIMEOUT = 600
	HIGH_ACCURACY = True
	RESOLVE_TAILCALLS = True
	RESOLVE_REGISTER_CALLS = True


class _smda:

	def _set_eng(self,fl,dis):
		self.file_path = fl._file_path
		self.fl        = fl
		self.base_addr = self.fl.getBaseAddress()
		self.disasm    = dis
		self.dobj	   = self.disasm.disassemble(self.fl.getData(), self.base_addr, timeout=Config.TIMEOUT)
		self.cfg 	   = self.dobj.collectCfg()

	@property
	def functions(self):
		return self.dobj.getFunctions()

	def _get_function(self,addr):
		if addr not in self.cfg:
			addr = self.dobj.ins2fn[addr]
		return AttrDict(self.cfg[addr])

def list_functions(**kwargs):
    return map(lambda f: Func(f),smda.functions)

smda = _smda()

def open(file):
	
	fl  = FileLoader(file, True)
	dis = Disassembler(Config)
	smda._set_eng(fl,dis)

	return smda


from .objects import *
