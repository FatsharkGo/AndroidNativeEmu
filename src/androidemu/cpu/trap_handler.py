import logging

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

logger = logging.getLogger(__name__)

class TrapHandler:
    def __init__(self, interrupt_handler, a64:bool):
        if a64:
            interrupt_handler.set_handler(7, self.__trap64)
        else:
            interrupt_handler.set_handler(7, self.__trap32)

    def __trap32(self, uc, intno, user_data, *args, **kwargs):
        lr = uc.reg_read(UC_ARM_REG_LR)
        logger.info("Trap at 0x{:08X}".format(lr))
        uc.reg_write(UC_ARM_REG_PC, lr)

    def __trap64(self, uc, intno, user_data, *args, **kwargs):
        lr = uc.reg_read(UC_ARM64_REG_LR)
        pc = uc.reg_read(UC_ARM64_REG_PC)
        logger.info("Trap at 0x{:08X} from 0x{:08X}".format(pc, lr))
        uc.reg_write(UC_ARM64_REG_PC, lr)


