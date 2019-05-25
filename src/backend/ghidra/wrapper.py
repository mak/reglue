from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import GenericAddress, AddressSet
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import RefType

from numbers import Number

is_number = lambda n: issubclass(type(n),Number)


class FakeIter(object):

    def __init__(self, iter_obj):
        self._obj  =  iter_obj


    def __iter__(self):
        return self

    def next(self):
        if self._obj.hasNext():
            return self._obj.next()
        else:
            raise StopIteration




class _ghidra:
    

    BB_FLOWS = (
        RefType.FALL_THROUGH,
        RefType.CONDITIONAL_JUMP,
        RefType.UNCONDITIONAL_JUMP,
        RefType.COMPUTED_JUMP,
        RefType.CONDITIONAL_COMPUTED_JUMP,
        RefType.JUMP_TERMINATOR
    )

    def __init__(self):
        self.cp = None

    def init(self, cp=None):

        if hasattr(globals(),'currentProgram'):
            self.cp    = currentProgram 
        elif cp:
            self.cp    = cp

        if self.cp:
            self.fmgr  = self.cp.getFunctionManager()
            self.afac  = self.cp.getAddressFactory()
            self.dtmgr = self.cp.getDataTypeManager()
            self.mem   = self.cp.getMemory()
            self.st    = self.cp.getSymbolTable()
            self.cm    = self.cp.getCodeManager()
            self.flatapi = FlatProgramAPI(self.cp)


    def to_address(self,n):
        if issubclass(type(n), GenericAddress):
            return n
        elif is_number(n):
            return self.afac.getAddress(hex(n))
        elif issubclass(type(n), basestring):
            s = self.get_symbol(a)
            if s:
                return a.address
            raise Exception('no such symbol!')

    def get_symbol(self, name):
        return self.st.getSymbol(name)

    def get_function(self, addr):
        addr = self.to_address(addr)
        f = self.fmgr.getFunctionAt(addr)
        if not f:
            f = self.fmgr.getFunctionContaining(addr)
        return f

    def get_basic_blocks_containing(self, addrset):
        bbm = BasicBlockModel(self.cp)
        bbi = bbm.getCodeBlocksContaining(addrset, self.flatapi.monitor)
        return FakeIter(bbi)

    def get_bb_destinations(self, bb):
        return FakeIter(bb.getDestinations(self.flatapi.monitor))

    def get_bb_sources(self, bb):
        return FakeIter(bb.getSources(self.flatapi.monitor))

    def get_bb_instructions(self,bb):
        ar = bb.getLastRange()
        return FakeIter(self.cm.getCodeUnits(AddressSet(ar),True))

