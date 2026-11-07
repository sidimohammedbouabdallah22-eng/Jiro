"""Windows scheduling diagnostics for an owned qualification VM process."""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import time


def ticks(value):
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--pid',type=int,required=True)
    args = parser.parse_args()
    directory = args.directory.resolve(strict=True)
    assert directory.parent == Path(__file__).resolve().parents[1]/'artifacts'
    assert directory.name.startswith('m4-business-abuse-')
    kernel = ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE,*([ctypes.POINTER(wintypes.FILETIME)]*4)]
    kernel.GetSystemTimes.argtypes = [ctypes.POINTER(wintypes.FILETIME)]*3
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000,False,args.pid)
    assert handle, 'cannot inspect the owned VM process'
    try:
        with (directory/'host-heartbeat.jsonl').open('x',buffering=1) as stream:
            for _ in range(1200):
                if (directory/'host-heartbeat.stop').exists():
                    break
                idle,host_kernel,host_user = [wintypes.FILETIME() for _ in range(3)]
                created,exited,vm_kernel,vm_user = [wintypes.FILETIME() for _ in range(4)]
                assert kernel.GetSystemTimes(ctypes.byref(idle),ctypes.byref(host_kernel),ctypes.byref(host_user))
                assert kernel.GetProcessTimes(handle,*[ctypes.byref(v) for v in [created,exited,vm_kernel,vm_user]])
                row = dict(monotonic=time.monotonic(),time=time.time(),pid=args.pid,
                    process_created_ticks=ticks(created),process_exited_ticks=ticks(exited),
                    host_idle_ticks=ticks(idle),host_kernel_ticks=ticks(host_kernel),host_user_ticks=ticks(host_user),
                    vm_kernel_ticks=ticks(vm_kernel),vm_user_ticks=ticks(vm_user))
                stream.write(json.dumps(row)+'\n')
                if row['process_exited_ticks']:
                    break
                time.sleep(1)
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    main()
