import sys
import logging

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

logger = logging.getLogger(__name__)


class InterruptHandler:

    """
    :type mu Uc
    """
    def __init__(self, mu, a64:bool):
        self._mu = mu
        self._mu.hook_add(UC_HOOK_INTR, self._hook_interrupt_a64 if a64 else self._hook_interrupt)
        self._handlers = dict()

    def _hook_interrupt(self, uc, intno, data):
        if intno in self._handlers:
            self._handlers[intno](uc)
        else:
            logger.error("Unhandled interrupt %d at %x, stopping emulation" % (intno, self._mu.reg_read(UC_ARM_REG_PC)))
            self._mu.emu_stop()
            sys.exit(-1)

    def _hook_interrupt_a64(self, uc, intno, data):
        if intno in self._handlers:
            self._handlers[intno](uc, intno, data)
        else:
            logger.error("Unhandled interrupt %d at %x, stopping emulation" % (intno, self._mu.reg_read(UC_ARM64_REG_PC)))
            self._mu.emu_stop()

    def set_handler(self, intno, handler):
        self._handlers[intno] = handler
