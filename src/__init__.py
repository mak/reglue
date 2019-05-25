
def get_module(eng):
    m = __import__('reglue.backend.'+eng)
    m = getattr(m,'backend')
    m = getattr(m,eng)
    return m
        

def get_engine(eng=None):
    def load_mod(imp_name, mname):
        try:
            __import__(imp_name)
            return mname, get_module(mname)
        except ImportError:
            return None

    if eng:
        return eng,get_module(eng)
    
    r = load_mod('idc','ida') or load_mod('binaryninja','binja') or load_mod('r2pip','r2') or \
        load_mod('mlib.disasm.eng','meng') or load_mod('smda','smda') or load_mod('ghidra','ghidra')
    if r is None:
        raise Exception('No supported engines!')
    return r
    
class Binary(object):

    __api_functions =  (
        'get_function',
        'list_functions',
        'list_sections',
        'read_bytes',
        'write_bytes',
    )

    __properties = { 
        'functions': 'list_functions',
        'sections' : 'list_sections'  
    }

    __api_aliases = {
        'function' : 'get_function',
        'get_functions':'list_functions',
        'get_sections' : 'list_sections'  

    }
    def __init__(self,binpath,eng=None,**kwargs):
        self.eng_name,self.engine = get_engine(eng)
        self.engine.open(binpath,**kwargs)
        
    def __getattr__(self,name):
        name = self.__api_aliases.get(name,name)

        if name in self.__properties:
            ## property is a function in engine
            ## without any arguments
            name = self.__properties[name]
            return getattr(self.engine,name)()

        elif name in self.__api_functions:
            return getattr(self.engine,name)
        raise Exception("No Such method")


    # def get_function(self,addr):
    #     return self.engine.Func(addr)
    # function = get_function

    # def list_functions(self,**kwargs):
    #     return self.engine.list_functions(**kwargs)
    # functions = property(list_functions)

    # def list_sections(self,**kwargs):
    #     return self.engine.list_sections(**kwargs)
    # sections = property(list_sections)
    
    # def read_bytes(self, addr, size):
    #     return self.engine.read_bytes(addr,size)



