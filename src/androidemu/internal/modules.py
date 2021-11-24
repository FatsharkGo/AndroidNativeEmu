from ctypes import ArgumentError
import os
import struct
import logging

from unicorn import UC_PROT_ALL,UC_PROT_WRITE,UC_PROT_READ

import lief
from . import elf_reader

from . import get_segment_protection, arm
from .module import Module
from .symbol_resolved import SymbolResolved


from ..memory import align

from ..utils import misc_utils

logger = logging.getLogger(__name__)


class Modules:
    """
    :type emu androidemu.emulator.Emulator
    :type modules list[Module]
    """
    def __init__(self, emu, vfs_root, a64:bool):
        self.emu = emu
        self.__search_path = set()
        self.modules = list()
        self.symbol_hooks = dict()
        self.__vfs_root = vfs_root
        self.__a64 = a64

    def add_symbol_hook(self, symbol_name, addr):
        self.symbol_hooks[symbol_name] = addr

    def find_symbol(self, addr):
        for module in self.modules:
            if addr in module.symbol_lookup:
                return module.symbol_lookup[addr]
        return None, None

    def find_symbol_name(self, name):
        return self._elf_lookup_symbol(name)

    def find_module(self, addr):
        for module in self.modules:
            if module.base == addr:
                return module
        return None

    def find_module_by_name(self, filename):
        absp1 = os.path.abspath(filename)
        for m in self.modules:
            absm = os.path.abspath(m.filename)
            if (absp1 == absm):
                return m

    def load_module(self, filename:str, do_init:bool=True, emu64=True):
        m = self.find_module_by_name(filename)
        if m is not None:
            return m
        logger.debug("Loading module '%s'" % filename)

        self.__search_path.add(os.path.dirname(os.path.abspath(filename)))
        reader = elf_reader.ELFReader(filename)
        if not (reader.is64() == emu64):
            raise ArgumentError("Emulator ARCH type mismatch target type.")

        # LOAD the parts need to be mapped into memory
        load_segments = reader.get_load()

        # Find bounds of the load segments.
        bound_low = 0
        bound_high = 0

        for segment in load_segments:
            if segment.virtual_size == 0:
                continue
            # Determine the address bound
            bound_low = min(bound_low, segment.virtual_address)
            bound_high = max(bound_high, segment.virtual_address + segment.virtual_size)

        # Retrieve a base address for this module.        
        (load_base, _) = self.emu.memory_manager.reserve_module(bound_high - bound_low)        
        logger.debug('   Base address: 0x{:08X}'.format(load_base))

        for segment in load_segments:
            prot = get_segment_protection(int(segment.flags))
            prot = prot if prot != 0 else UC_PROT_ALL
            
            (seg_addr, seg_size) = align(load_base + segment.virtual_address, segment.virtual_size, True)

            logger.info("   Map [0x{:08X}, 0x{:08X}): 0x{:08X} | RWX".format(seg_addr, seg_addr+seg_size, seg_size))
            self.emu.mu.mem_map(seg_addr, seg_size, prot)
            self.emu.mu.mem_write(load_base + segment.virtual_address, bytes(segment.content))

        # Load needed
        so_needed = reader.get_so_need()
        if len(so_needed) > 0:
            logger.info("   Deps: {}".format(' '.join(so_needed)))
        for so_name in so_needed:
            fpn_needed = None
            path = misc_utils.vfs_path_to_system_path(self.__vfs_root, so_name, reader.is64())
            if (not os.path.exists(path)):
                for sp in self.__search_path:
                    if os.path.exists(os.path.join(sp, so_name)):
                        fpn_needed = os.path.join(sp, so_name)
                        break
            else:
                fpn_needed = path
            if fpn_needed is None:
                logger.warn("%s needed by %s do not exist in vfs %s"%(so_name, filename, self.__vfs_root))
                continue
            else:
                libmod = self.load_module(fpn_needed, do_init, emu64)

        # Resolve all symbols
        symbols = reader.get_symbols()
        symbols_resolved = dict()
        for symbol in symbols:
            symbol_address = self._elf_get_symval(load_base, symbol)
            if symbol_address is not None:
                symbols_resolved[symbol.name] = SymbolResolved(symbol_address, symbol)

        # Relocate
        for rel in reader.get_rels():
            rel_addr = load_base + rel.address
            rel_info_type = rel.type

            # https://static.docs.arm.com/ihi0044/e/IHI0044E_aaelf.pdf
            # Relocation table for ARM
            if rel_info_type == arm.R_ARM_ABS32:
                if rel.symbol.name in symbols_resolved:
                    sym_addr = symbols_resolved[rel.symbol.name].address
                    # Read value
                    offset = int.from_bytes(self.emu.mu.mem_read(rel_addr, 0), byteorder='little')
                    # Create the new value
                    value = sym_addr + offset
                    # Check thumb
                    if rel.symbol.type == lief.ELF.SYMBOL_TYPES.FUNC:
                        value = value | 1
                    # Write the new value
                    self.emu.mu.mem_write(rel_addr, value.to_bytes(8 if self.__a64 else 4, byteorder='little'))
            elif rel_info_type in (arm.R_ARM_GLOB_DAT, arm.R_ARM_JUMP_SLOT, 
                                            arm.R_AARCH64_GLOB_DAT, arm.R_AARCH64_JUMP_SLOT):
                # Resolve the symbol
                if rel.symbol.name in symbols_resolved:
                    value = symbols_resolved[rel.symbol.name].address
                # Write the new value
                self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
            elif rel_info_type in (arm.R_ARM_RELATIVE,):
                if rel.symbol.value == 0:
                    # Load addres at which it was linked originally
                    value_orig_bytes = self.emu.mu.mem_read(rel_addr, 8 if self.__a64 else 4)
                    value_orig = int.from_bytes(value_orig_bytes, byteorder='little')
                    # Create the new value
                    value = load_base + value_orig
                    # Write the new value
                    self.emu.mu.mem_write(rel_addr, value.to_bytes(8 if self.__a64 else 4, byteorder='little'))
                else:
                    raise NotImplementedError("Relocation type not support")
            elif rel_info_type in (arm.R_AARCH64_RELATIVE,):
                if rel.symbol.value == 0:
                    # Create the new value
                    value = load_base + rel.addend
                    # Write the new value
                    self.emu.mu.mem_write(rel_addr, value.to_bytes(8, byteorder='little'))
                else:
                    raise NotImplementedError("Relocation type not support")
            elif rel_info_type in (arm.R_AARCH64_ABS64,):
                value = load_base + rel.symbol.value
                self.emu.mu.mem_write(rel_addr, value.to_bytes(8, byteorder='little'))
            else:
                raise NotImplementedError("Relocation type({}) not support.".format(rel_info_type))

        # Prepare the init array
        init_array = reader.get_init_array(load_base)

        # store information about loaded module
        module = Module(filename, load_base, bound_high-bound_low, symbols_resolved, init_array, reader.get_entry_point(load_base))
        self.modules.append(module)

        # Do the init
        if do_init:
            module.call_init(self.emu)

        logger.info("Finish load lib %s -> 0x%08X"%(filename, load_base))
        return module

    def _elf_get_symval(self, elf_base: int, symbol: lief.ELF.Symbol):
        if symbol.name in self.symbol_hooks:
            return self.symbol_hooks[symbol.name]

        if symbol.shndx == int(lief.ELF.SYMBOL_SECTION_INDEX.UNDEF):
            # External symbol, lookup value.
            target = self._elf_lookup_symbol(symbol.name)
            if target is None:
                # Extern symbol not found
                if symbol.binding == lief.ELF.SYMBOL_BINDINGS.WEAK:
                    # Weak symbol initialized as 0
                    return 0
                else:
                    if symbol.name != '':
                        logger.error('   ! Undefined external symbol: %s' % symbol.name)
                    return None
            else:
                return target
        elif symbol.shndx == int(lief.ELF.SYMBOL_SECTION_INDEX.ABS):
            # Absolute symbol.
            return elf_base + symbol.value
        else:
            # Internally defined symbol.
            return elf_base + symbol.value

    def _elf_lookup_symbol(self, name):
        for module in self.modules:
            if name in module.symbols:
                symbol = module.symbols[name]

                if symbol.address != 0:
                    return symbol.address

        return None

    def __iter__(self):
        for x in self.modules:
            yield x
