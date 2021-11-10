import logging
import os

from unicorn import Uc, UcError, UC_PROT_READ, UC_PROT_WRITE, UC_ERR_MAP
from ..utils.misc_utils import page_end, page_start

from . import *
from .allocator_heap import HeapAllocator
from .allocator_incremental import IncrementalAllocator

logger = logging.getLogger(__name__)
class MemoryManager:

    def __init__(self, uc: Uc):
        self._uc = uc
        self._heap = HeapAllocator(HEAP_MIN, HEAP_MAX, uc)
        self._modules = IncrementalAllocator(MODULES_MIN, MODULES_MAX)
        self._mappings = IncrementalAllocator(MAPPING_MIN, MAPPING_MAX)
        self.__file_map_addr = {}

    def allocate(self, size: int) -> int:
        """
        Allocate bytes on the heap.
        """
        return self._heap.allocate(size)

    def free(self, addr: int):
        """
        Free bytes on the heap.
        """
        self._heap.free(addr)

    def reserve_module(self, size) -> tuple[int, int]:
        """
        Reserve bytes for a module.
        The caller is responsible for mapping the address into Unicorn.
        """
        return self._modules.reserve(size)

    def mapping_map(self, size: int, prot: int) -> tuple[int, int]:
        """
        Memory mapping for the mmap syscall.
        """
        (addr, size_aligned) = self._mappings.reserve(size)

        logger.info("Map [0x{:08X}, 0x{:08X}): 0x{:08X} | ?".format(addr, addr+size_aligned, size_aligned))
        self._uc.mem_map(addr, size_aligned, prot)

        return (addr, size_aligned)

    def mapping_unmap(self, addr: int, size: int):
        """
        Memory unmapping for the unmap syscall.
        """
        if MAPPING_MIN <= addr <= MAPPING_MAX:
            self._uc.mem_unmap(addr, size)

    def mapping_protect(self, addr: int, size: int, prot: int):
        """
        Memory unmapping for the unmap syscall.
        """
        if MAPPING_MIN <= addr <= MAPPING_MAX:
            self._uc.mem_protect(addr, size, prot)

    def __mapping_fixed(self, address:int, size:int, prot=UC_PROT_READ|UC_PROT_WRITE) -> tuple[int, int]:
        """
        Mapping a fixed address
        """
        try:
            self._uc.mem_map(address, size, prot)
        except UcError as e:
            if e.errno == UC_ERR_MAP:
                blocks = set()
                extra_protect = set()
                for b in range(address, address+size, 0x1000):
                    blocks.add(b)
                for r in self._uc.mem_regions():
                    raddr = r[0]
                    rend = r[1] + 1
                    for b in range(raddr, rend, 0x1000):
                        if b in blocks:
                            blocks.remove(b)
                            extra_protect.add(b)
                for b_map in blocks:
                    self._uc.mem_map(b_map, 0x1000, prot)
                for b_protect in extra_protect:
                    self._uc.mem_protect(b_protect, 0x1000, prot)
        return (address, size)

    def __read_fully(self, fd, size):
        b_read = os.read(fd, size)
        sz_read = len(b_read)
        if (sz_read <= 0):
            return b_read

        sz_left = size - sz_read
        while (sz_left > 0):
            this_read = os.read(fd, sz_left)
            len_this_read = len(this_read)
            logger.debug (len_this_read)
            if (len_this_read <= 0):
                break
            b_read = b_read + this_read
            sz_left = sz_left - len_this_read
        return b_read

    def mapping_file(self, address, size, prot, vf, file_offset) -> tuple[int, int]:
        """
        Mapping a virtual file

        """
        if address % PAGE_SIZE != 0:
            raise Exception("Map address 0x{:08X} is not multiple by page size 0x{:08X}".format(address, PAGE_SIZE))

        al_address = address
        al_size = page_end(al_address+size) - al_address
        (res_addr, res_size) = self.__mapping_fixed(al_address, al_size, prot)
        if res_addr != -1 and vf != None:
            ori_off = os.lseek(vf.descriptor, 0, os.SEEK_CUR)
            os.lseek(vf.descriptor, file_offset, os.SEEK_SET)
            data = self.__read_fully(vf.descriptor, size)
            logger.debug("Read back {} bytes from offset {} for {} bytes".format(len(data), file_offset, size))
            self._uc.mem_write(res_addr, data)
            self.__file_map_addr[al_address] = (al_address+al_size, file_offset, vf)
            os.lseek(vf.descriptor, ori_off, os.SEEK_SET)
        return (res_addr, res_size)


    def check_addr(self , addr, prot):
        for r in self._uc.mem_regions():
            if (addr>=r[0] and addr < r[1] and prot & r[2]):
                return True
        return False

    def __get_map_attr(self, start, end):
        for addr in self.__file_map_addr:
            v = self.__file_map_addr[addr]
            mstart = addr
            mend = v[0]
            if (start >= mstart and end <= mend):
                vf = v[2]
                return v[1], vf.name
        return 0, ""

    def __get_attrs(self, region):           
        r = "r" if region[2] & 0x1 else "-"
        w = "w" if region[2] & 0x2 else "-"
        x = "x" if region[2] & 0x4 else "-"
        prot = "%s%s%sp"%(r,w,x)
        off, name = self.__get_map_attr(region[0], region[1]+1)
        return (region[0], region[1]+1, prot, off, name)

    def dump_maps(self, stream):
        regions = []
        for region in self._uc.mem_regions():
            regions.append(region)

        regions.sort()
        
        '''
        for region in regions:
            print("region begin :0x%08X end:0x%08X, prot:%d"%(region[0], region[1], region[2]))
        #
        '''
        
        n = len(regions)
        if (n < 1):
            return
        output=[]
        last_attr = self.__get_attrs(regions[0])
        start = last_attr[0]
        for i in range(1, n): 
            region = regions[i]
            attr = self.__get_attrs(region)
            if (last_attr[1] == attr[0] and last_attr[2:] == attr[2:]):
                pass
            else:
                output.append((start,)+last_attr[1:])
                start = attr[0]
            last_attr = attr
        output.append((start,)+last_attr[1:])

        for item in output:
            line = "%08x-%08x %s %08x 00:00 0 \t\t %s\n"%(item[0], item[1], item[2], item[3], item[4])
            stream.write(line)

