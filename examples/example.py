import logging
import posixpath
import sys

from unicorn import UC_HOOK_CODE, UC_PROT_EXEC
from unicorn.arm_const import *

from androidemu.emulator import Emulator
import androidemu.utils.debug_utils
from androidemu.utils.chain_log import ChainLogger


g_cfd = ChainLogger(sys.stdout, "./ins-native.log")

# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    aarch64=False,
    vfp_inst_set=True,
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs"))

lib_module = emulator.load_library("example_binaries/32/libnative-lib.so", emu64=False)

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("[0x%x] %s" % (module.base, module.filename))


# Add debugging.
def hook_code(mu, address, size, user_data):
    try:
        emu = user_data
        if (not emu.memory_manager.check_addr(address, UC_PROT_EXEC)):
            logger.error("addr 0x%08X out of range"%(address,))
            sys.exit(-1)

        #androidemu.utils.debug_utils.dump_registers(mu, sys.stdout)
        androidemu.utils.debug_utils.dump_code(emu, address, size, g_cfd)
    except Exception as e:
        logger.exception("exception in hook_code")
        sys.exit(-1)

emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)

# Runs a method of "libnative-lib.so" that calls an imported function "strlen" from "libc.so".
emulator.call_symbol(lib_module, '_Z4testv')

print("String length is: %i" % emulator.mu.reg_read(UC_ARM_REG_R0))
