import struct
import inspect

from unicorn import Uc
from unicorn.arm_const import *
from unicorn.arm64_const import *

from ...hooker import STACK_OFFSET
from ..java_class_def import JavaClassDef
from ..jni_const import JNI_ERR
from ..jni_ref import jobject, jstring, jobjectArray, jbyteArray, jclass


def native_write_args(emu, *argv):
    amount = len(argv)

    if amount == 0:
        return

    if emu.a64:
        # Argument passing rules for aarch64, see:
        #   https://developer.arm.com/documentation/ihi0055/d/
        rx=[UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
            UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        rv=[UC_ARM64_REG_V0, UC_ARM64_REG_V1, UC_ARM64_REG_V2, UC_ARM64_REG_V3,
            UC_ARM64_REG_V4, UC_ARM64_REG_V5, UC_ARM64_REG_V6, UC_ARM64_REG_V7]
        for arg in argv:
            if type(arg) is float:
                if len(rv) > 0:
                    native_write_arg_register(emu, rv.pop(0), arg)
                else:
                    sp_start = emu.mu.reg_read(UC_ARM64_REG_SP)
                    sp_current = sp_start - STACK_OFFSET
                    sp_current = sp_current - (8 * (amount - 8))
                    sp_end = sp_current
                    for arg in argv[8:]:
                        emu.mu.mem_write(sp_current, native_translate_arg(emu, arg).to_bytes(8, byteorder='little'))
                        sp_current = sp_current + 8
                    emu.mu.reg_write(UC_ARM64_REG_SP, sp_end)
            else:
                if len(rx) > 0:
                    native_write_arg_register(emu, rx.pop(0), arg)
                else:
                    sp_start = emu.mu.reg_read(UC_ARM64_REG_SP)
                    sp_current = sp_start - STACK_OFFSET
                    sp_current = sp_current - (8 * (amount - 8))
                    sp_end = sp_current
                    for arg in argv[8:]:
                        emu.mu.mem_write(sp_current, native_translate_arg(emu, arg).to_bytes(8, byteorder='little'))
                        sp_current = sp_current + 8
                    emu.mu.reg_write(UC_ARM64_REG_SP, sp_end)
    else:
        if amount >= 1:
            native_write_arg_register(emu, UC_ARM_REG_R0, argv[0])
        if amount >= 2:
            native_write_arg_register(emu, UC_ARM_REG_R1, argv[1])    
        if amount >= 3:
            native_write_arg_register(emu, UC_ARM_REG_R2, argv[2])    
        if amount >= 4:
            native_write_arg_register(emu, UC_ARM_REG_R3, argv[3])    
        if amount >= 5:
            sp_start = emu.mu.reg_read(UC_ARM_REG_SP)
            sp_current = sp_start - STACK_OFFSET  # Need to offset because our hook pushes one register on the stack.
            sp_current = sp_current - (4 * (amount - 4))  # Reserve space for arguments.
            sp_end = sp_current    
            for arg in argv[4:]:
                emu.mu.mem_write(sp_current, native_translate_arg(emu, arg).to_bytes(4, byteorder='little'))
                sp_current = sp_current + 4    
            emu.mu.reg_write(UC_ARM_REG_SP, sp_end)


def native_read_args(mu, args_count, a64:bool):
    native_args = []

    if a64:
        if args_count >= 1:
            native_args.append(mu.reg_read(UC_ARM64_REG_X0))
        if args_count >= 2:
            native_args.append(mu.reg_read(UC_ARM64_REG_X1))
        if args_count >= 3:
            native_args.append(mu.reg_read(UC_ARM64_REG_X2))
        if args_count >= 4:
            native_args.append(mu.reg_read(UC_ARM64_REG_X3))
        if args_count >= 5:
            native_args.append(mu.reg_read(UC_ARM64_REG_X4))
        if args_count >= 6:
            native_args.append(mu.reg_read(UC_ARM64_REG_X5))
        if args_count >= 7:
            native_args.append(mu.reg_read(UC_ARM64_REG_X6))
        if args_count >= 8:
            native_args.append(mu.reg_read(UC_ARM64_REG_X7))
        sp = mu.reg_read(UC_ARM64_REG_SP)
        sp = sp + STACK_OFFSET  # Need to offset by 4 because our hook pushes one register on the stack.    
        if args_count >= 9:
            for x in range(0, args_count - 8):
                native_args.append(int.from_bytes(mu.mem_read(sp + (x * 8), 8), byteorder='little'))
    else:
        if args_count >= 1:
            native_args.append(mu.reg_read(UC_ARM_REG_R0))    
        if args_count >= 2:
            native_args.append(mu.reg_read(UC_ARM_REG_R1))    
        if args_count >= 3:
            native_args.append(mu.reg_read(UC_ARM_REG_R2))    
        if args_count >= 4:
            native_args.append(mu.reg_read(UC_ARM_REG_R3))    
        sp = mu.reg_read(UC_ARM_REG_SP)
        sp = sp + STACK_OFFSET  # Need to offset by 4 because our hook pushes one register on the stack.    
        if args_count >= 5:
            for x in range(0, args_count - 4):
                native_args.append(int.from_bytes(mu.mem_read(sp + (x * 4), 4), byteorder='little'))

    return native_args


def native_translate_arg(emu, val):
    if isinstance(val, int):
        return val
    elif isinstance(val, float):
        return int.from_bytes(struct.pack('<d', val), 'little')
    elif isinstance(val, str):
        return emu.java_vm.jni_env.add_local_reference(jstring(val))
    elif isinstance(val, list):
        return emu.java_vm.jni_env.add_local_reference(jobjectArray(val))
    elif isinstance(val, bytearray):
        return emu.java_vm.jni_env.add_local_reference(jbyteArray(val))
    elif isinstance(type(val), JavaClassDef):
        # TODO: Look into this, seems wrong..
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    elif isinstance(val, JavaClassDef):
        return emu.java_vm.jni_env.add_local_reference(jclass(val))
    else:
        raise NotImplementedError("Unable to write response '%s' type '%s' to emulator." % (str(val), type(val)))


def native_write_arg_register(emu, reg, val):
    emu.mu.reg_write(reg, native_translate_arg(emu, val))


def native_method(func):
    def native_method_wrapper(*argv):
        """
        :type self
        :type emu androidemu.emulator.Emulator
        :type mu Uc
        """

        emu = argv[1] if len(argv) == 2 else argv[0]
        mu = emu.mu

        args = inspect.getfullargspec(func).args
        args_count = len(args) - (2 if 'self' in args else 1)

        if args_count < 0:
            raise RuntimeError("NativeMethod accept at least (self, mu) or (mu).")

        native_args = native_read_args(mu, args_count, emu.a64)

        if len(argv) == 1:
            result = func(mu, *native_args)
        else:
            result = func(argv[0], mu, *native_args)

        if result is not None:
            if(isinstance(result, tuple)):
                rlow = result[0]
                rhigh = result[1]
                native_write_arg_register(emu, UC_ARM_REG_R0, rlow)
                native_write_arg_register(emu, UC_ARM_REG_R1, rhigh)
            else:
                native_write_arg_register(emu, UC_ARM_REG_R0, result)

    return native_method_wrapper
