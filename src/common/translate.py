x86_opcode_translate = {
    'je' : 'jz',
    'jne': 'jnz',
    'jae': 'jnb',
    'jnc': 'jnb',
    'ret': 'retn',
    'movsb': 'movs',
    'movsw': 'movs',
    'movsd': 'movs',
    'movsq': 'movs',
    'cmpsb': 'cmps',
    'cmpsw': 'cmps',
    'cmpsd': 'cmps',
    'cmpsq': 'cmps',
    'stosb': 'stos',
    'stosw': 'stos',
    'stosd': 'stos',
    'stosq': 'stos',
    'lodsb': 'lods',
    'lodsw': 'lods',
    'lodsd': 'lods',
    'lodsq': 'lods',
    'scasb': 'scas',
    'scasw': 'scas',
    'scasd': 'scas',
    'scasq': 'scas',
}


def translate_mnem(mnem,arch):
    d = globals()[arch + '_opcode_translate']
    return d.get(mnem,mnem)