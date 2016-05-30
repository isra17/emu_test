import struct
import logging
import unicorn
from elftools.elf.elffile import ELFFile

PF_E = 0b001
PF_W = 0b010
PF_R = 0b100

def aligned_size(size, page_size=0x1000):
    return (size//page_size + 1) * page_size

def aligned_addr(addr, page_size=0x1000):
    return (addr//page_size) * page_size

class EmuElf:
    def __init__(self, fd):
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.elffile = ELFFile(fd)

        self._init_unicorn_from_elf(fd)
        self._init_stack()
        self._init_gdt()
        self._init_tls()

        self.uc.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED, self.on_fetch_unmapped)
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.on_code)

    def on_fetch_unmapped(self, uc, type, address, size, value, user_data):
        print("On fetch unmapped: addr: 0x{:x}, rip: 0x{:x}, rbp: 0x{:x}, rsp: 0x{:x}".format(
            address,
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP),
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RBP),
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RSP)))

    def on_code(self, *args):
        print("On code: rip: 0x{:x}, rbp: 0x{:x}, rsp: 0x{:x}".format(
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP),
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RBP),
            self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RSP)))


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
        for symbol in self.elffile.get_section_by_name('.symtab').iter_symbols():
            if symbol.entry.st_info.type == 'STT_FUNC':
                self._func_map[symbol.name] = symbol.entry.st_value

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
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP, self._sp - 8)

    def _init_tls(self):
        self.tls_addr = 0x7f200000
        self.uc.mem_map(self.tls_addr, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        self.gdt_write(1, self.tls_addr, 0x1, 0x12, 0)
        self.uc.reg_write(unicorn.x86_const.UC_X86_REG_FS, 1)

    # Inspired from https://github.com/lunixbochs/usercorn/tree/master/go/arch/x86/linux.go
    def gdt_write(self, selector, base, limit, access, flags):
        entry = limit & 0xffff
        entry |= ((limit >> 16) & 0xF) << 48
        entry |= (base & 0xFFFFFF) << 16
        entry |= ((base >> 24) & 0xFF) << 56
        entry |= (access & 0xFF) << 40
        entry |= (flags & 0xFF) << 52

        self.uc.mem_write(self.gdt_addr + 8 * selector, struct.pack('<Q', entry))

    def call(self, fn_name):
        func_addr = self._func_map[fn_name]
        self.uc.emu_start(func_addr, 0)

def run_benchmark(path, tests):
    fd = open(path, 'rb')
    emu = EmuElf(fd)
    emu.call('test_1')

if __name__ == '__main__':
    run_benchmark(path='./tests', tests=['test_1'])
