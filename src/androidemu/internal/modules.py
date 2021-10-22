import logging

from unicorn import UC_PROT_ALL,UC_PROT_WRITE,UC_PROT_READ

from .symbol_resolved import SymbolResolved

from . import arm
from ..utils.misc_utils import get_segment_protection,page_end, page_start
from .module import Module
from ..utils import memory_helpers,misc_utils
from ..vfs.virtual_file import VirtualFile
from .. import config
from . import elf_reader
import os

logger = logging.getLogger(__name__)

class Modules:
    """
    :type emu androidemu.emulator.Emulator
    :type modules list[Module]
    """
    def __init__(self, emu, vfs_root):
        self.emu = emu
        self.__search_path = set()
        self.modules = list()
        self.symbol_hooks = dict()
        self.counter_memory = config.BASE_ADDR
        self.__vfs_root = vfs_root
        soinfo_area_sz = 0x40000; 
        self.__soinfo_area_base = emu.memory.map(0, soinfo_area_sz, UC_PROT_WRITE | UC_PROT_READ)

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
            #
        #
    #
    
    def mem_reserve(self, start, end):
        size_aligned = page_end(end) - page_start(start)
        ret = self.counter_memory
        self.counter_memory += size_aligned
        return ret
    #

    def load_module(self, filename, do_init=True):
        m = self.find_module_by_name(filename)
        if (m != None):
            return m
        #
        logger.info("Loading module '%s'" % filename)
        #do sth like linker
        self.__search_path.add(os.path.dirname(os.path.abspath(filename)))
        reader = elf_reader.ELFFile(filename)

        # Parse program header (Execution view).

        # - LOAD (determinate what parts of the ELF file get mapped into memory)
        load_segments = reader.get_load()

        # Find bounds of the load segments.
        bound_low = 0
        bound_high = 0

        for segment in load_segments:
            if segment.header.p_memsz == 0:
                continue

            if bound_low > segment.header.p_vaddr:
                bound_low = segment.header.p_vaddr

            high = segment.header.p_vaddr + segment.header.p_memsz

            if bound_high < high:
                bound_high = high


        # Retrieve a base address for this module.
        load_base = self.mem_reserve(bound_low, bound_high)

        logger.debug('=> Base address: 0x%x' % load_base)

        vf = VirtualFile(misc_utils.system_path_to_vfs_path(self.__vfs_root, filename), misc_utils.my_open(filename, os.O_RDONLY), filename)
        for segment in load_segments:
            prot = get_segment_protection(segment.header.p_flags)
            prot = prot if prot != 0 else UC_PROT_ALL
            
            #p_vaddr = segment["p_vaddr"]
            seg_start = load_base + segment.header.p_vaddr
            seg_page_start = page_start(seg_start)
            #p_offset = segment["p_offset"]
            file_start = segment.header.p_offset
            #p_filesz = segment["p_filesz"]
            file_end = file_start + segment.header.p_filesz
            file_page_start = page_start(file_start)
            file_length = file_end - file_page_start
            assert(file_length>0)
            if (file_length > 0):
                self.emu.memory.map(seg_page_start, file_length, prot, vf, file_page_start)
            #
            #p_memsz = segment["p_memsz"]
            seg_end   = seg_start + segment.header.p_memsz
            seg_page_end = page_end(seg_end)

            seg_file_end = seg_start+segment.header.p_filesz

            seg_file_end = page_end(seg_file_end)
            '''
                    void* zeromap = mmap((void*)seg_file_end,
                        seg_page_end - seg_file_end,
                        PFLAGS_TO_PROT(phdr->p_flags),
                        MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
                        -1,
                        0);
            '''
            self.emu.memory.map(seg_file_end, seg_page_end-seg_file_end, prot)
        #

        # Load needed
        so_needed = reader.get_so_need()
        for so_name in so_needed:
            fpn_needed = None
            path = misc_utils.vfs_path_to_system_path(self.__vfs_root, so_name, True if reader.elfclass==64 else False)
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
                libmod = self.load_module(fpn_needed)

        # Find init array.
        init_array_offset, init_array_size, init_array = reader.get_init_array(load_base)
        init_offset = reader.get_init()

        # Resolve all symbols.
        symbols = reader.get_symbols()
        symbols_resolved = dict()
        for symbol in symbols:
            symbol_address = self._elf_get_symval(load_base, symbol)
            if symbol_address is not None:
                symbols_resolved[symbol.name] = SymbolResolved(symbol_address, symbol)

        # Relocate.
        for rel_tbl in reader.get_rels().values():
            for rel in rel_tbl:
                sym = symbols[rel['r_info_sym']]
                sym_value = sym['st_value']
    
                rel_addr = load_base + rel['r_offset']  # Location where relocation should happen
                rel_info_type = rel['r_info_type']
    
                # https://static.docs.arm.com/ihi0044/e/IHI0044E_aaelf.pdf
                # Relocation table for ARM
                if rel_info_type == arm.R_ARM_ABS32:
                    if sym.name in symbols_resolved:
                        sym_addr = symbols_resolved[sym.name].address
                        # Read value.
                        offset = int.from_bytes(self.emu.mu.mem_read(rel_addr, 4), byteorder='little')
                        # Create the new value.
                        value = sym_addr + offset
                        # Check thumb.
                        if sym['st_info']['type'] == 'STT_FUNC':
                            value = value | 1
                        # Write the new value
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                elif rel_info_type in (arm.R_ARM_GLOB_DAT, arm.R_ARM_JUMP_SLOT, 
                                                arm.R_AARCH64_GLOB_DAT, arm.R_AARCH64_JUMP_SLOT):
                    # Resolve the symbol.
                    if sym.name in symbols_resolved:
                        value = symbols_resolved[sym.name].address
    
                        # Write the new value
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                elif rel_info_type in (arm.R_ARM_RELATIVE, arm.R_AARCH64_RELATIVE):
                    if sym_value == 0:
                        # Load address at which it was linked originally.
                        value_orig_bytes = self.emu.mu.mem_read(rel_addr, 4)
                        value_orig = int.from_bytes(value_orig_bytes, byteorder='little')
    
                        # Create the new value
                        value = load_base + value_orig
    
                        # Write the new value
                        self.emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder='little'))
                    else:
                        raise NotImplementedError()
                else:
                    logger.error("Unhandled relocation type %i." % rel_info_type)

        if (init_offset != 0):
            init_array.append(load_base+init_offset)

        #write_sz = reader.write_soinfo(self.emu.mu, load_base, self.__soinfo_area_base)

        # Store information about loaded module.
        module = Module(filename, load_base, bound_high - bound_low, symbols_resolved, init_array, self.__soinfo_area_base)
        self.modules.append(module)
        
        #self.__soinfo_area_base += write_sz
        #TODO init tls like linker
        '''
        void __libc_init_tls(KernelArgumentBlock& args) {
            __libc_auxv = args.auxv;
            unsigned stack_top = (__get_sp() & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
            unsigned stack_size = 128 * 1024;
            unsigned stack_bottom = stack_top - stack_size;
            static void* tls[BIONIC_TLS_SLOTS];
            static pthread_internal_t thread;
            thread.tid = gettid();
            thread.tls = tls;
            pthread_attr_init(&thread.attr);
            pthread_attr_setstack(&thread.attr, (void*) stack_bottom, stack_size);
            _init_thread(&thread, false);
            __init_tls(&thread);
            tls[TLS_SLOT_BIONIC_PREINIT] = &args;
        }
        '''
        if do_init:
            '''
            for r in self.emu.mu.mem_regions():
                print("region begin :0x%08X end:0x%08X, prot:%d"%(r[0], r[1], r[2]))
            #
            '''
            module.call_init(self.emu)
        #
        logger.info("finish load lib %s base 0x%08X"%(filename, load_base))
        return module
    #

    def _elf_get_symval(self, elf_base, symbol):
        if symbol.name in self.symbol_hooks:
            return self.symbol_hooks[symbol.name]

        if symbol['st_shndx'] == 'SHN_UNDEF':
            # External symbol, lookup value.
            target = self._elf_lookup_symbol(symbol.name)
            if target is None:
                # Extern symbol not found
                if symbol['st_info']['bind'] == 'STB_WEAK':
                    # Weak symbol initialized as 0
                    return 0
                else:
                    logger.error('=> Undefined external symbol: %s' % symbol.name)
                    return None
            else:
                return target
        elif symbol['st_shndx'] == 'SHN_ABS':
            # Absolute symbol.
            return elf_base + symbol['st_value']
        else:
            # Internally defined symbol.
            return elf_base + symbol['st_value']

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
