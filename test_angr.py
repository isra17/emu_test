import logging
import angr
import simuvex

def call_bench(fn, p):
    result_addr = p.loader.main_bin.get_symbol('result').addr
    res = fn('asd')
    assert fn.result_state.se.any_int(res) == 0
    res = fn('foo')
    assert fn.result_state.se.any_int(res) != 0

def test_angr_strcmp(benchmark):
    p = angr.Project('./bench', load_options={'auto_load_libs': False})
    fn_addr = p.loader.main_bin.get_symbol('test1').addr
    cc = p.factory.cc(func_ty=simuvex.s_type.parse_defns('int x(char* data);')['x'])
    testfn = p.factory.callable(fn_addr, cc=cc, toc=None, concrete_only=True)
    benchmark(call_bench, testfn, p)

