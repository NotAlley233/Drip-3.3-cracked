"""Shared read-only Windows process bindings for runtime discovery and readback."""
import ctypes as c
from ctypes import wintypes as w

kernel = c.WinDLL('kernel32', use_last_error=True)


class MBI(c.Structure):
    _fields_ = [('BaseAddress', c.c_void_p), ('AllocationBase', c.c_void_p),
                ('AllocationProtect', w.DWORD), ('PartitionId', w.WORD),
                ('RegionSize', c.c_size_t), ('State', w.DWORD),
                ('Protect', w.DWORD), ('Type', w.DWORD)]


kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
kernel.OpenProcess.restype = w.HANDLE
kernel.CloseHandle.argtypes = [w.HANDLE]
kernel.VirtualQueryEx.argtypes = [w.HANDLE, c.c_void_p, c.POINTER(MBI), c.c_size_t]
kernel.VirtualQueryEx.restype = c.c_size_t
kernel.ReadProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
kernel.ReadProcessMemory.restype = w.BOOL
kernel.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
kernel.QueryFullProcessImageNameW.restype = w.BOOL


def read(handle, address, size):
    buffer = c.create_string_buffer(size)
    count = c.c_size_t()
    if not kernel.ReadProcessMemory(handle, address, buffer, size, c.byref(count)) or count.value != size:
        raise OSError(c.get_last_error(), 'ReadProcessMemory failed at ' + hex(address) + ', bytes=' + str(count.value))
    return buffer.raw
