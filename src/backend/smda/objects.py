
from reglue.common import CsInstr
from reglue.common.abstract import *

from . import smda


class Graph(BaseGraph):
	EdgeClass = BaseEdge

	def load(self,rels, bbs ):
		self._parents = []
		for i,_bb in enumerate(bbs):
			self._parents.append([])
			bb = BasicBlock(i,self,_bb)
			bb.load( bbs[_bb], rels.get(_bb,[]))
			self._bbs.append(bb)
			self._addrs_to_ids[bb.address]=i

class Func(BaseFunc):

	def __init__(self,addr):

		self._func = smda._get_function(addr)
		self.address = self._func.offset 


	@property
	def graph(self):
		g = Graph(self)
		g.load(self._func.blockrefs,self._func.blocks)
		g._build_graph()
		return g


class BasicBlock(BaseBasicBlock):

	def __init__(self,id, g, addr):
		self.g  = g
		self.id = id
		self.address = addr
		self.start_ea = addr

	def load(self,bb_instr,bb_rels):
		self._succs = bb_rels
		self._instr = bb_instr

	@property
	def children(self):
		return (self.g.at(a) for a in self._succs)

	def __iter__(self):

		for _i in self._instr:
			i = Instr(_i[0], _i[1])
			yield i		

class Instr(CsInstr):

	def get_arch(self):
		return 'x86'

	def get_bits(self):
		return smda.dobj.bitness

	def data_refs(self):
		return smda.dobj.data_refs_from.get(self.address,[])


