"""Discover a fresh injected instance using read-only identity checks."""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import struct

from process_memory import kernel, read, MBI


def process_image(pid):
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        name = c.create_unicode_buffer(32768)
        count = w.DWORD(len(name))
        return name.value if kernel.QueryFullProcessImageNameW(handle, 0, name, c.byref(count)) else None
    finally:
        kernel.CloseHandle(handle)


def discover(panel):
    import frida
    manifest = json.loads((Path(panel)/'identity.json').read_text())
    processes = frida.get_local_device().enumerate_processes()
    loaders = []
    for process in processes:
        if process.name.lower() != 'drip.exe':
            continue
        image = process_image(process.pid)
        if image and hashlib.sha256(Path(image).read_bytes()).hexdigest() == manifest['loader_sha256']:
            loaders.append({'pid':process.pid,'image':image,'expected_sha256':manifest['loader_sha256']})
    if not loaders:
        raise RuntimeError('Waiting for the existing injector (Drip.exe)')
    if len(loaders) != 1:
        raise RuntimeError('Multiple verified injectors found; close duplicate instances')
    candidates = []
    for process in processes:
        if process.name.lower() != 'javaw.exe':
            continue
        handle = kernel.OpenProcess(0x410, False, process.pid)
        if not handle:
            continue
        try:
            address = 0
            seen = set()
            while address < 0x7fffffffffff:
                region = MBI()
                if not kernel.VirtualQueryEx(handle,address,c.byref(region),c.sizeof(region)):
                    break
                following = (region.BaseAddress or 0)+region.RegionSize
                if following <= address:
                    break
                address = following
                base = region.AllocationBase or 0
                if base in seen or region.State != 0x1000 or (region.Protect & 255) not in (0x10,0x20,0x40,0x80):
                    continue
                seen.add(base)
                try:
                    header = read(handle,base,4096)
                    if header[:2] != b'MZ':
                        continue
                    pe = struct.unpack_from('<I',header,60)[0]
                    if pe+84 > len(header) or header[pe:pe+4] != b'PE\0\0':
                        continue
                    if struct.unpack_from('<I',header,pe+80)[0] != manifest['image_size']:
                        continue
                    if any(read(handle,base+int(item['rva'],16),len(bytes.fromhex(item['hex']))) != bytes.fromhex(item['hex']) for item in manifest['signatures']):
                        continue
                    pointer = lambda at: struct.unpack('<Q',read(handle,at,8))[0]
                    root = pointer(base+0x465688)
                    config = pointer(root)
                    read(handle,config,1752)
                    for module in manifest['modules']:
                        obj = pointer(base+int(module['object_slot_rva'],16))
                        if pointer(obj) != base+int(module['vtable_rva'],16):
                            raise ValueError('Module table not ready')
                    candidates.append({'pid':process.pid,'module_base':hex(base),'root':hex(root),'config':hex(config)})
                except (OSError,ValueError,struct.error):
                    continue
        finally:
            kernel.CloseHandle(handle)
    if len(candidates) != 1:
        raise RuntimeError('Waiting for one verified injected game' if not candidates else 'Multiple injected games found; keep one instance')
    return candidates[0], loaders[0]
