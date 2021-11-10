import json
import os
import pathlib
from os import stat_result

from unicorn import Uc

from ..config import WRITE_FSTAT_TIMES


def stat64(path: pathlib.Path):
    meta_path = path.with_suffix(".meta_emu")

    if not os.path.exists(meta_path):
        meta_path_dir = os.path.dirname(meta_path)

        if not os.path.isdir(meta_path_dir):
            os.makedirs(meta_path_dir)

        with open(meta_path, 'w') as f:
            json.dump({
                'st_dev': 0,
                '__st_ino': 0,
                'st_mode': 0,
                'st_nlink': 0,
                'st_uid': 0,
                'st_gid': 0,
                'st_rdev': 0,
                'st_size': 0,
                'st_blksize': 0,
                'st_blocks': 0,
                'st_atime': 0,
                'st_atime_ns': 0,
                'st_mtime': 0,
                'st_mtime_ns': 0,
                'st_ctime': 0,
                'st_ctime_ns': 0,
                'st_ino': 0
            }, fp=f, indent=4)

    with open(meta_path, 'r') as f:
        return json.load(fp=f)


def stat_to_memory(uc: Uc, buf_ptr, stat, write_times):
    uc.mem_write(buf_ptr, stat['st_dev'].to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 8, int(0).to_bytes(4, byteorder='little'))  # PAD 4
    uc.mem_write(buf_ptr + 12, stat['__st_ino'].to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 16, stat['st_mode'].to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 20, stat['st_nlink'].to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 24, stat['st_uid'].to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 28, stat['st_gid'].to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 32, stat['st_rdev'].to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 40, int(0).to_bytes(4, byteorder='little'))  # PAD 4
    uc.mem_write(buf_ptr + 44, int(0).to_bytes(4, byteorder='little'))  # PAD 4
    uc.mem_write(buf_ptr + 48, stat['st_size'].to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 56, stat['st_blksize'].to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 60, int(0).to_bytes(4, byteorder='little'))  # PAD 4
    uc.mem_write(buf_ptr + 64, stat['st_blocks'].to_bytes(8, byteorder='little'))

    if write_times:
        uc.mem_write(buf_ptr + 72, stat['st_atime'].to_bytes(4, byteorder='little'))
        uc.mem_write(buf_ptr + 76, stat['st_atime_ns'].to_bytes(4, byteorder='little'))
        uc.mem_write(buf_ptr + 80, stat['st_mtime'].to_bytes(4, byteorder='little'))
        uc.mem_write(buf_ptr + 84, stat['st_mtime_ns'].to_bytes(4, byteorder='little'))
        uc.mem_write(buf_ptr + 88, stat['st_ctime'].to_bytes(4, byteorder='little'))
        uc.mem_write(buf_ptr + 92, stat['st_ctime_ns'].to_bytes(4, byteorder='little'))
    else:
        uc.mem_write(buf_ptr + 72, int(0).to_bytes(4, byteorder='little'))
        uc.mem_write(buf_ptr + 76, int(0).to_bytes(4, byteorder='little'))
        uc.mem_write(buf_ptr + 80, int(0).to_bytes(4, byteorder='little'))
        uc.mem_write(buf_ptr + 84, int(0).to_bytes(4, byteorder='little'))
        uc.mem_write(buf_ptr + 88, int(0).to_bytes(4, byteorder='little'))
        uc.mem_write(buf_ptr + 92, int(0).to_bytes(4, byteorder='little'))

    uc.mem_write(buf_ptr + 96, stat['st_ino'].to_bytes(8, byteorder='little'))


def stat_to_memory2(uc, buf_ptr, stat, uid):
    '''
    unsigned long long st_dev; 
    unsigned char __pad0[4]; 
    unsigned long __st_ino; 
    unsigned int st_mode; 
    nlink_t st_nlink;  4
    uid_t st_uid;  4
    gid_t st_gid; 4
    unsigned long long st_rdev; 
    unsigned char __pad3[4]; 
    long long st_size; 
    unsigned long st_blksize; 
    unsigned long long st_blocks; 
    struct timespec st_atim;  8
    struct timespec st_mtim;  8
    struct timespec st_ctim;  8
    unsigned long long st_ino; 

    '''
    st_rdev = 0
    if (hasattr(stat, "st_rdev")):
        st_rdev = stat.st_rdev

    st_blksize = 0
    if (hasattr(stat, "st_blksize")):
        st_blksize = stat.st_blksize

    st_blocks = 0
    if (hasattr(stat, "st_blocks")):
        st_blocks = stat.st_blocks

    stdev = stat.st_dev
    if (stdev < 0):
        # Any value is OK
        stdev = stdev * -1

    uc.mem_write(buf_ptr, int(stdev).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 8, int(0).to_bytes(4, byteorder='little'))  # PAD 4
    uc.mem_write(buf_ptr + 12, int(stat.st_ino).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 16, int(stat.st_mode).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 20, int(stat.st_nlink).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 24, int(uid).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 28, int(uid).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 32, int(st_rdev).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 40, int(0).to_bytes(4, byteorder='little'))  # PAD 4
    uc.mem_write(buf_ptr + 48, int(stat.st_size).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 56, int(st_blksize).to_bytes(4, byteorder='little'))
    uc.mem_write(buf_ptr + 64, int(st_blocks).to_bytes(8, byteorder='little'))

    uc.mem_write(buf_ptr + 72, int(stat.st_atime).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 80, int(stat.st_mtime).to_bytes(8, byteorder='little'))
    uc.mem_write(buf_ptr + 88, int(stat.st_ctime).to_bytes(8, byteorder='little'))

    uc.mem_write(buf_ptr + 96, int(stat.st_ino).to_bytes(8, byteorder='little'))

