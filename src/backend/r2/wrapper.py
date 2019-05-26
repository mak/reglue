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