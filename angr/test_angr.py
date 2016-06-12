import logging
import angr
from simuvex.s_type import SimTypeFunction, SimTypeInt

angr.simos.SimLinux.SYSCALL_TABLE['X86'][192] = ('mmap_pgoff', 'mmap')

def test_callable_1():
    p = angr.Project('./tests', load_options={'auto_load_libs': False})
    proto = SimTypeFunction((), SimTypeInt())
    state = p.factory.full_init_state(args=['./test_1'])
    fn_addr = p.loader.main_bin.get_symbol('test_1').addr
    testfn = p.factory.callable(fn_addr, base_state=state, cc=p.factory.cc(func_ty=proto), toc=None, concrete_only=True)
    testfn.perform_call()

logging.getLogger('angr').setLevel(logging.DEBUG)
test_callable_1()

