import logging
import angr
from simuvex.s_type import SimTypeFunction, SimTypeInt

angr.simos.SimLinux.SYSCALL_TABLE['X86'][192] = ('mmap_pgoff', 'mmap')

def test_callable_1(benchmark):
    p = angr.Project('./tests', load_options={'auto_load_libs': False})
    proto = SimTypeFunction((), SimTypeInt())
    fn_addr = p.loader.main_bin.get_symbol('test_3').addr
    testfn = p.factory.callable(fn_addr, cc=p.factory.cc(func_ty=proto), toc=None, concrete_only=True)
    benchmark(testfn.perform_call)

