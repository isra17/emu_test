import struct
import logging
import unicorn
import capstone
from elftools.elf.elffile import ELFFile

PF_E = 0b001
PF_W = 0b010
PF_R = 0b100

F_GRANULARITY = 0x8
F_PROT_32 = 0x4
F_LONG = 0x2
F_AVAILABLE = 0x1

A_PRESENT = 0x80

A_PRIV_3 = 0x60
A_PRIV_2 = 0x40
A_PRIV_1 = 0x20
A_PRIV_0 = 0x0

A_CODE = 0x18
A_DATA = 0x10
A_TSS = 0x0
A_GATE = 0x0

A_DIR_BIT = 0x4
A_CON_BIT = 0x4

A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2

S_GDT = 0x0
S_LDT = 0x4
S_PRIV_3 = 0x3
S_PRIV_2 = 0x2
S_PRIV_1 = 0x1
S_PRIV_0 = 0x0


def aligned_size(size, page_size=0x1000):
    return (size//page_size + 1) * page_size

def aligned_addr(addr, page_size=0x1000):
    return (addr//page_size) * page_size

def create_gdt_entry(base, limit, access, flags):
    to_ret = limit & 0xffff;
    to_ret |= (base & 0xffffff) << 16;
    to_ret |= (access & 0xff) << 40;
    to_ret |= ((limit >> 16) & 0xf) << 48;
    to_ret |= (flags & 0xff) << 52;
    to_ret |= ((base >> 24) & 0xff) << 56;
    return struct.pack('<Q',to_ret)

def create_selector(idx, flags):
    to_ret = flags
    to_ret |= idx << 3
    return to_ret

class UniDebug:
    REGS_MAPPING = {
        'eax': unicorn.x86_const.UC_X86_REG_EAX,
        'ebx': unicorn.x86_const.UC_X86_REG_EBX,
        'ecx': unicorn.x86_const.UC_X86_REG_ECX,
        'edx': unicorn.x86_const.UC_X86_REG_EDX,
        'edi': unicorn.x86_const.UC_X86_REG_EDI,
        'esi': unicorn.x86_const.UC_X86_REG_ESI,
        'eip': unicorn.x86_const.UC_X86_REG_EIP,
        'esp': unicorn.x86_const.UC_X86_REG_ESP,
        'ebp': unicorn.x86_const.UC_X86_REG_EBP,
    }

    def __init__(self, emu):
        self.uc = emu.uc
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.on_code)
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    def on_code(self, handle, address, size, user_data):
        print("On code: eip: 0x{:x}, ebp: 0x{:x}, esp: 0x{:x}".format(
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EIP),
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EBP),
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP)))

        instr = self.uc.mem_read(address, size)
        disas = self.cs.disasm(bytes(instr), address).next()
        print("0x{0.address:08x}:\t{0.mnemonic}\t{0.op_str}".format(disas))

        while True:
            cmd = raw_input('>')
            if not cmd or cmd == 's':
                break
            args = cmd.split(' ')
            if args[0] == 'x':
                if args[1] in self.REGS_MAPPING:
                    reg = self.REGS_MAPPING[args[1]]
                    addr = self.uc.reg_read(reg)
                else:
                    addr = int(args[1], 16)
                data = None
                try:
                    data, = struct.unpack('<I', self.uc.mem_read(addr, 4))
                except:
                    pass
                if data:
                    print('0x{:08x}: 0x{:08x}'.format(addr, data))
                else:
                    print('0x{:08x}'.format(addr))
            elif args[0] == 'stack':
                self.dump_stack()
            else:
                print('Unknown command')

    def dump_stack(self):
        sp = self.sp()
        while sp <= self._sp-4:
            value, = struct.unpack('<I', self.read(sp, 4))
            print('0x{:08x}: 0x{:08x}'.format(sp, value))
            sp += 4


class EmuElf:
    def __init__(self, fd):
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.elffile = ELFFile(fd)
        self.brk = 0x7f400000

        self._init_unicorn_from_elf(fd)
        self._init_stack()
        self._init_gdt()
        self._init_segments_selectors()

        # Exit code.
        self.uc.mem_map(0x7f300000, 0x1000, unicorn.UC_PROT_EXEC)

        self.uc.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, self.on_unmapped)
        self.uc.hook_add(unicorn.UC_HOOK_INTR, self.on_intr)

    def on_intr(self, uc, intno, user_data):
        print("On intr: eip: 0x{:x}, eax: 0x{:x}, ebx: 0x{:x}".format(
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EIP),
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EAX),
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EBX)))

        syscall = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EAX)
        arg1 = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EBX)
        if syscall == 0x2d: # sys_brk(size)
            new_brk = arg1
            size = new_brk - self.brk
            if size > 0:
                self.uc.mem_map(self.brk, size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
                self.brk = new_brk
            self.uc.reg_write(unicorn.x86_const.UC_X86_REG_EAX, self.brk)

    def on_unmapped(self, uc, type, address, size, value, user_data):
        print("On fetch unmapped: addr: 0x{:x}, eip: 0x{:x}, ebp: 0x{:x}, esp: 0x{:x}".format(
            address,
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EIP),
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EBP),
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP)))

    def _init_unicorn_from_elf(self, fd):
        for segment in self.elffile.iter_segments():
            p_type =  segment.header.p_type
            p_flags =  segment.header.p_flags
            if p_type == 'PT_LOAD':
                perms = 0
                if p_flags & PF_E:
                    perms |= unicorn.UC_PROT_EXEC
                if p_flags & PF_W:
                    perms |= unicorn.UC_PROT_WRITE
                if p_flags & PF_R:
                    perms |= unicorn.UC_PROT_READ
                page_addr = aligned_addr(segment.header.p_vaddr)
                offset = segment.header.p_vaddr - page_addr
                page_size = aligned_size(segment.header.p_memsz + offset)
                self.uc.mem_map(page_addr, page_size, perms)
                self.uc.mem_write(segment.header.p_vaddr, segment.data())

        self._func_map = {}
        self._object_map = {}
        for symbol in self.elffile.get_section_by_name('.symtab').iter_symbols():
            if symbol.entry.st_info.type == 'STT_FUNC':
                self._func_map[symbol.name] = symbol.entry.st_value
            if symbol.entry.st_info.type == 'STT_OBJECT':
                self._object_map[symbol.name] = symbol.entry.st_value

    def _init_gdt(self):
        self.gdt_addr = 0x7f100000
        self.uc.mem_map(self.gdt_addr, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_GDTR, (0, self.gdt_addr, 0x1000, 0))

    def _init_stack(self):
        self._sp = 0x7ffff000
        self._sp_size = 0xf000
        self.uc.mem_map(self._sp - self._sp_size,
                        self._sp_size,
                        unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

    def _init_segments_selectors(self):
        # TLS segments
        self.tls_addr = 0x7f201000
        self.uc.mem_map(self.tls_addr-0x1000, 0x2000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

        gdt_entry = create_gdt_entry(self.tls_addr, 0xfffff, A_PRESENT | A_PRIV_3 | A_DATA | A_DATA_WRITABLE, F_PROT_32 | F_GRANULARITY)
        self.uc.mem_write(self.gdt_addr + 8 * 0x1, gdt_entry)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_GS, create_selector(0x1, S_PRIV_3))

        # Code segment
        gdt_entry = create_gdt_entry(0, 0xfffff, A_PRESENT | A_PRIV_3 | A_CODE | A_CODE_READABLE, F_PROT_32 | F_GRANULARITY)
        self.uc.mem_write(self.gdt_addr + 8 * 0x2, gdt_entry)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_CS, create_selector(0x2, S_PRIV_3))

        # Stack segment
        gdt_entry = create_gdt_entry(0, 0xfffff, A_PRESENT | A_PRIV_0 | A_DATA | A_DATA_WRITABLE, F_PROT_32 | F_GRANULARITY)
        self.uc.mem_write(self.gdt_addr + 8 * 0x3, gdt_entry)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_SS, create_selector(0x3, S_PRIV_0))

        # Data segments
        gdt_entry = create_gdt_entry(0, 0xfffff, A_PRESENT | A_PRIV_3 | A_DATA | A_DATA_WRITABLE, F_PROT_32 | F_GRANULARITY)
        self.uc.mem_write(self.gdt_addr + 8 * 0x4, gdt_entry)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_DS, create_selector(0x4, S_PRIV_3))
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_ES, create_selector(0x4, S_PRIV_3))

    def push(self, val):
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_ESP, self.sp() - 4)
        self.uc.mem_write(self.sp(), struct.pack('<I', val))

    def sp(self):
        return self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP)

    def call(self, fn_name, until=None):
        func_addr = self._func_map[fn_name]
        until_addr = 0x7f300000
        if until:
            until_addr = self._func_map[until]
        self.push(until_addr)
        self.uc.emu_start(func_addr, until_addr)
        return self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EAX)

    def reset_sp(self):
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_ESP, self._sp)

    def read(self, addr, size):
        return self.uc.mem_read(addr, size)


def call_test_strcmp(emu):
    emu.reset_sp()
    emu.push(struct.unpack('<I', 'asd\x00')[0])
    emu.push(emu.sp())
    assert emu.call('test1') == 0

    emu.reset_sp()
    emu.push(struct.unpack('<I', 'foo\x00')[0])
    emu.push(emu.sp())
    assert emu.call('test1') != 0

def call_test_sha256(emu):
    emu.reset_sp()
    emu.push(struct.unpack('<I', 'abc\x00')[0])
    emu.push(emu.sp())
    emu.call('test2')
    assert str(emu.read(emu._object_map['result'], 32)).encode('hex') == \
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

def test_unicorn_strcmp(benchmark):
    with open('./bench', 'rb') as fd:
        emu = EmuElf(fd)
        benchmark(call_test_strcmp, emu)

def test_unicorn_sha256(benchmark):
    with open('./bench', 'rb') as fd:
        emu = EmuElf(fd)
        benchmark(call_test_sha256, emu)

