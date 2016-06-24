import vivisect
import struct

vw = vivisect.VivWorkspace()
vw.loadFromFile('./bench')
emu_addr = 0x10000000
emu = vw.getEmulator()
emu.addMemoryMap(emu_addr, 6, "[emu]", '\x00'*0x100)

def call_fn(emu, name, args):
    addr = vw.vaByName(name)
    ret_addr = 0xdeadbeef

    cc = emu.getCallingConvention('stdcall')
    cc.executeCall(emu, addr, args=args, ra=ret_addr)
    while emu.getProgramCounter() != ret_addr:
        pc = emu.getProgramCounter()
        op = emu.parseOpcode(pc)
        emu.executeOpcode(op)

    regs = emu.getRegisters()
    return regs['eax']

def call_test_1():
    emu.writeMemory(emu_addr, 'asd\x00')
    assert call_fn(emu, 'bench.test1', [emu_addr]) == 0

    emu.writeMemory(emu_addr, 'foo\x00')
    assert call_fn(emu, 'bench.test1', [emu_addr]) != 0

def test_vivisect_1(benchmark):
    benchmark(call_test_1)

