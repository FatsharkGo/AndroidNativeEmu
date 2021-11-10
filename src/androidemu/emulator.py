import logging
import os
import sys
import importlib
import inspect
import pkgutil
from random import randint

import hexdump
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_ARCH_ARM64
from unicorn.unicorn_const import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_C13_C0_3

from . import config
from .cpu.interrupt_handler import InterruptHandler
from .cpu.syscall_handlers import SyscallHandlers
from .cpu.syscall_hooks import SyscallHooks
from .cpu.syscall_hooks_memory import SyscallHooksMemory
from .hooker import Hooker
from .internal.modules import Modules
from .java.helpers.native_method import native_write_args
from .java.java_classloader import JavaClassLoader
from .java.java_vm import JavaVM
from .memory import STACK_ADDR, STACK_SIZE, HOOK_MEMORY_BASE, HOOK_MEMORY_SIZE
from .memory.memory_manager import MemoryManager
from .native.hooks import NativeHooks
from .tracer import Tracer
from .utils.memory_helpers import write_utf8
from .vfs.file_system import VirtualFileSystem
from .vfs.virtual_file import VirtualFile
from .utils import misc_utils
from .java.java_class_def import JavaClassDef

logger = logging.getLogger(__name__)


class Emulator:
    """
    :type mu Uc
    :type modules Modules
    """
    def __init__(self, vfs_root: str = None, config_path: str = "default.json", aarch64: bool = True, vfp_inst_set: bool = True):
        config.global_config_init(config_path)
        # Unicorn.
        self.__vfs_root = vfs_root
        self._a64 = aarch64
        if self._a64:
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        else:
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        if vfp_inst_set:
            self._enable_vfp()
            
        logger.info("Map [0x{:08X}, 0x{:08X}): 0x{:08X} | RW".format(0, 0x00001000, 0x00001000))
        self.mu.mem_map(0x0, 0x00001000, UC_PROT_READ | UC_PROT_WRITE)

        # Android
        self.system_properties = {"libc.debug.malloc.options": ""}

        # Stack.
        logger.info("Map [0x{:08X}, 0x{:08X}): 0x{:08X} | RW".format(STACK_ADDR, STACK_ADDR+STACK_SIZE, STACK_SIZE))
        self.mu.mem_map(STACK_ADDR, STACK_SIZE)
        self.mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE)

        # Executable data.
        self.modules = Modules(self, self.__vfs_root)
        self.memory_manager = MemoryManager(self.mu)

        # CPU
        self.interrupt_handler = InterruptHandler(self.mu)
        self.syscall_handler = SyscallHandlers(self.interrupt_handler)
        self.syscall_hooks = SyscallHooks(self.mu, self.syscall_handler, self.modules)
        self.syscall_hooks_memory = SyscallHooksMemory(self.mu, self.memory_manager, self.syscall_handler)

        # File System
        if vfs_root is not None:
            self.vfs = VirtualFileSystem(vfs_root, self.syscall_handler, self.memory_manager)
        else:
            self.vfs = None

        # Hooker
        logger.info("Map [0x{:08X}, 0x{:08X}): 0x{:08X} | RW".format(HOOK_MEMORY_BASE, HOOK_MEMORY_BASE+HOOK_MEMORY_BASE, HOOK_MEMORY_BASE))
        self.mu.mem_map(HOOK_MEMORY_BASE, HOOK_MEMORY_SIZE)
        self.hooker = Hooker(self, HOOK_MEMORY_BASE, HOOK_MEMORY_SIZE)

        # JavaVM
        self.java_classloader = JavaClassLoader()
        self.java_vm = JavaVM(self, self.java_classloader, self.hooker)

        # Native
        self.native_hooks = NativeHooks(self, self.memory_manager, self.modules, self.hooker)

        # JNI
        self.__add_classes()

        # Trivial files mapping
        path = "%s/system/lib/vectors"%vfs_root
        vf = VirtualFile("[vectors]", misc_utils.my_open(path, os.O_RDONLY), path)
        self.memory_manager.mapping_file(0xffff0000, 0x1000, UC_PROT_EXEC | UC_PROT_READ, vf, 0)

        path = "%s/system/bin/app_process32"%vfs_root
        sz = os.path.getsize(path)
        vf = VirtualFile("/system/bin/app_process32", misc_utils.my_open(path, os.O_RDONLY), path)
        self.memory_manager.mapping_file(0xab006000, sz, UC_PROT_WRITE | UC_PROT_READ, vf, 0)

        # Tracer
        self.tracer = Tracer(self.mu, self.modules)

        # Thread.
        self._setup_thread_register()

    # https://github.com/unicorn-engine/unicorn/blob/8c6cbe3f3cabed57b23b721c29f937dd5baafc90/tests/regress/arm_fp_vfp_disabled.py#L15
    def _enable_vfp(self):
        # MRC p15, #0, r1, c1, c0, #2
        # ORR r1, r1, #(0xf << 20)
        # MCR p15, #0, r1, c1, c0, #2
        # MOV r1, #0
        # MCR p15, #0, r1, c7, c5, #4
        # MOV r0,#0x40000000
        # FMXR FPEXC, r0
        code = '11EE501F'
        code += '41F47001'
        code += '01EE501F'
        code += '4FF00001'
        code += '07EE951F'
        code += '4FF08040'
        code += 'E8EE100A'
        # vpush {d8}
        code += '2ded028b'

        address = 0x1000
        mem_size = 0x1000
        code_bytes = bytes.fromhex(code)

        try:
            logger.info("Map [0x{:08X}, 0x{:08X}): 0x{:08X} | RW".format(address, address+mem_size, mem_size))
            self.mu.mem_map(address, mem_size)
            self.mu.mem_write(address, code_bytes)
            self.mu.reg_write(UC_ARM_REG_SP, address + mem_size)

            self.mu.emu_start(address | 1, address + len(code_bytes))
        finally:
            self.mu.mem_unmap(address, mem_size)


    def __add_classes(self):
        cur_file_dir = os.path.dirname(__file__)
        entry_file_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        #python 约定 package_name总是相对于入口脚本目录
        #package_name = os.path.relpath(cur_file_dir, entry_file_dir).replace("/", ".")
        package_name = os.path.basename(cur_file_dir)

        full_dirname = "%s/java/classes"%(cur_file_dir, )

        preload_classes = set()
        for importer, mod_name, c in pkgutil.iter_modules([full_dirname]):
            import_name = ".java.classes.%s"%mod_name
            m = importlib.import_module(import_name, package_name)
            #print(dir(m))
            clsList = inspect.getmembers(m, inspect.isclass)
            for _, clz in clsList:
                if (type(clz) == JavaClassDef):
                    preload_classes.add(clz)
                #
            #
        #
        for clz in preload_classes:
            self.java_classloader.add_class(clz)
        #

        #also add classloader as java class
        self.java_classloader.add_class(JavaClassLoader)


    def _setup_thread_register(self):
        """
        Set up thread register.
        This is currently not accurate and just filled with garbage to ensure the emulator does not crash.

        https://developer.arm.com/documentation/ddi0211/k/system-control-coprocessor/system-control-coprocessor-register-descriptions/c13--thread-and-process-id-registers
        """
        thread_info_size = 64
        thread_info = self.memory_manager.allocate(thread_info_size * 5)

        thread_info_1 = thread_info + (thread_info_size * 0)
        thread_info_2 = thread_info + (thread_info_size * 1)
        thread_info_3 = thread_info + (thread_info_size * 2)
        thread_info_4 = thread_info + (thread_info_size * 3)
        thread_info_5 = thread_info + (thread_info_size * 4)

        # Thread name
        write_utf8(self.mu, thread_info_5, "AndroidNativeEmu")

        # R4
        self.mu.mem_write(thread_info_2 + 0x4, int(thread_info_5).to_bytes(4, byteorder='little'))
        self.mu.mem_write(thread_info_2 + 0xC, int(thread_info_3).to_bytes(4, byteorder='little'))

        # R1
        self.mu.mem_write(thread_info_1 + 0x4, int(thread_info_4).to_bytes(4, byteorder='little'))
        self.mu.mem_write(thread_info_1 + 0xC, int(thread_info_2).to_bytes(4, byteorder='little'))
        self.mu.reg_write(UC_ARM_REG_C13_C0_3, thread_info_1)

    def load_library(self, filename, do_init=True, emu64=True):
        libmod = self.modules.load_module(filename, do_init, emu64)
        return libmod

    def call_symbol(self, module, symbol_name, *argv):
        symbol = module.find_symbol(symbol_name)

        if symbol is None:
            logger.error('Unable to find symbol \'%s\' in module \'%s\'.' % (symbol_name, module.filename))
            return

        return self.call_native(symbol.address, *argv)

    def call_native(self, addr, *argv):
        # Detect JNI call
        is_jni = False

        if len(argv) >= 1:
            is_jni = argv[0] == self.java_vm.address_ptr or argv[0] == self.java_vm.jni_env.address_ptr

        # TODO: Write JNI args to local ref table if jni.

        try:
            # Execute native call.
            self.mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE)
            native_write_args(self, *argv)
            stop_pos = randint(HOOK_MEMORY_BASE, HOOK_MEMORY_BASE + HOOK_MEMORY_SIZE) | 1
            self.mu.reg_write(UC_ARM_REG_LR, stop_pos)
            self.mu.emu_start(addr, stop_pos - 1)

            # Read result from locals if jni.
            if is_jni:
                result_idx = self.mu.reg_read(UC_ARM_REG_R0)
                result = self.java_vm.jni_env.get_local_reference(result_idx)

                if result is None:
                    return result

                return result.value
            else:
                return self.mu.reg_read(UC_ARM_REG_R0)
        finally:
            # Clear locals if jni.
            if is_jni:
                self.java_vm.jni_env.clear_locals()

    def dump(self, out_dir):
        os.makedirs(out_dir)

        for begin, end, prot in [reg for reg in self.mu.mem_regions()]:
            filename = "{:#010x}-{:#010x}.bin".format(begin, end)
            pathname = os.path.join(out_dir, filename)
            with open(pathname, "w") as f:
                f.write(hexdump.hexdump(self.mu.mem_read(begin, end - begin), result='return'))
