import logging
import angr
from simuvex.s_type import SimTypeFunction, SimTypeInt

angr.simos.SimLinux.SYSCALL_TABLE['X86'][192] = ('mmap_pgoff', 'mmap')

def call_bench(fn, p):
    result_addr = p.loader.main_bin.get_symbol('result').addr
    fn.perform_call('abc')
    s = fn.result_state
    assert s.se.any_str(s.memory.load(result_addr, 32)) == \
        '\\\x0c\x81[\x0f\x16\xb9!\xca\x94\xe4\xcdKG\xba\x03\xb4\t\xf2\x92@j-' \
        '\xab.H\xac\xfa-\xacF\xea'

def test_angr(benchmark):
    p = angr.Project('./bench', load_options={'auto_load_libs': False})
    fn_addr = p.loader.main_bin.get_symbol('test').addr
    testfn = p.factory.callable(fn_addr, toc=None, concrete_only=True)
    benchmark(call_bench, testfn, p)

#test_angr(lambda a, b, c: a(b,c))
