import r2pipe


class r2:

    @staticmethod
    def get_basicblocks(addr):
        return r2cmd(r2obj,'afbj','0x%x'%addr)

    @staticmethod
    def cmd(cmd,*args):
        return r2cmd(r2obj,cmd,*args)


    @staticmethod
    def add_zignature(name,type,data):
        return r2cmd(r2obj,'za',name,type,data)

    @staticmethod
    def get_address_info(addr):
        return r2cmd(r2obj,'ai',hex(addr))

def r2cmd(robj,cmd,*args):
    f = 'cmd'
    if cmd.endswith('j'):
        f += 'j'
    if args:
       cmd = cmd + ' ' + ' '.join(args)
    log_cmd(cmd)
    return getattr(robj,f)(cmd)

def log_cmd(cmd):
    import sys
    if True:
        print >> sys.stderr, cmd

def list_functions(only_exec=False):
    for fdat in r2.cmd('aflj'):
        f = Func(fdat['offset'])
        f.load(fdat)
        yield f
    
signatures = {
    "__SEH_prolog":  {"name":"seh","bytes":"68........64a1........50648925000000008b......896c24108d......2be05356578b....89....508b....c7............89....c3","graph":{"cc":"1","nbbs":"1","edges":"0","ebbs":"1"},"offset":4230984,"refs":[] }
}

        
r2obj = None
def open(f):
    global r2obj
    r2obj = r2pipe.open(f)
    r2cmd(r2obj,'e','io.cache=true')
    r2cmd(r2obj,'e','asm.bytes=false')
    ## can't do that...
    #r2cmd(r2obj,'aaa')

    if r2cmd(r2obj,'ij')['bin']['bintype'] == 'pe' and\
       bool(r2cmd(r2obj,'ii~msvcrt.dll__except_handler')):

       ## define __SEH_prolog
       r2.cmd('k','anal/types/__SEH_prolog=func')
       r2.cmd('k','anal/types/func.__SEH_prolog.args=2')
       r2.cmd('k','anal/types/func.__SEH_prolog.arg.0=LPVOID,SEHRecord')
       r2.cmd('k','anal/types/func.__SEH_prolog.arg.1=long,StackSize')
       r2.cmd('k','anal/types/func.__SEH_prolog.ret=long')
       r2.cmd('k','anal/types/func.__SEH_prolog.cc=cdecl')       
       ## add zignature to find _SEH_prolog
    for s in signatures:
        z = signatures[s]
        r2.add_zignature(s,'b',z['bytes'])
    r2.cmd('z/')

        
    r2.cmd('aab')
    r2.cmd('aa')
    r2.cmd('aei')
#    r2cmd(r2obj,'aaE')
    r2.cmd('aan')
    for hit in r2.cmd('zij'):
        n = hit['name'][11:-2]
        r2.cmd('afs','0x%x'%hit['offset'],n)
    return r2


from .objects import *
