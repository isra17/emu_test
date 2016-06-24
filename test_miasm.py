from miasm2.analysis.sandbox import Sandbox_Linux_x86_32
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE

parser = Sandbox_Linux_x86_32.parser(description="ELF sandboxer")
emu_addr = 0x10000000

def call_test_strcmp(sb):
    fva = sb.elf.getsectionbyname('.symtab')['test1'].value

    sb.jitter.set_str_ansi(emu_addr, 'asd')
    sb.jitter.push_uint32_t(emu_addr)
    sb.jitter.push_uint32_t(0x1337beef)

    sb.run(fva)
    assert sb.jitter.cpu.EAX == 0

    sb.jitter.set_str_ansi(emu_addr, 'foo')
    sb.jitter.push_uint32_t(emu_addr)
    sb.jitter.push_uint32_t(0x1337beef)
    sb.run(fva)
    assert sb.jitter.cpu.EAX != 0

def call_test_sha256(sb):
    fva = sb.elf.getsectionbyname('.symtab')['test2'].value
    result_va = sb.elf.getsectionbyname('.symtab')['result'].value

    sb.jitter.set_str_ansi(emu_addr, 'abc')
    sb.jitter.push_uint32_t(emu_addr)
    sb.jitter.push_uint32_t(0x1337beef)

    sb.run(fva)

    print(sb.jitter.vm.get_mem(result_va, 32).encode('hex'))


def test_miasm_python_strcmp(benchmark):
    options = parser.parse_args(['-j','python'])
    sb = Sandbox_Linux_x86_32('./bench', options, globals())
    sb.jitter.vm.add_memory_page(emu_addr, PAGE_READ | PAGE_WRITE, '\x00'*0x100, '[emu]')
    benchmark(call_test_strcmp, sb)

def test_miasm_gcc_strcmp(benchmark):
    options = parser.parse_args(['-j','gcc'])
    sb = Sandbox_Linux_x86_32('./bench', options, globals())
    sb.jitter.vm.add_memory_page(emu_addr, PAGE_READ | PAGE_WRITE, '\x00'*0x100, '[emu]')
    benchmark(call_test_strcmp, sb)

def test_miasm_gcc_sha256(benchmark):
    options = parser.parse_args(['-j','gcc'])
    sb = Sandbox_Linux_x86_32('./bench', options, globals())
    sb.jitter.vm.add_memory_page(emu_addr, PAGE_READ | PAGE_WRITE, '\x00'*0x100, '[emu]')
    benchmark(call_test_sha256, sb)

