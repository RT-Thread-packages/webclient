from building import *

cwd     = GetCurrentDir()
src     = Glob('*.c')
CPPPATH = [cwd]

group = DefineGroup('WebClient', src, depend = ['RT_USING_LWIP','PKG_USING_WEBCLIENT'], CPPPATH = CPPPATH)

Return('group')
