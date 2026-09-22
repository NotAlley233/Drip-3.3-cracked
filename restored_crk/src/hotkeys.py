"""Foreground-only, edge-triggered Windows keys for panel-managed bindings."""
import ctypes as c
from ctypes import wintypes as w


class KeyEdges:
    def __init__(self):
        self.previous = set()
        self.focused = False
        self.bindings = None

    def update(self, bindings, down, focused):
        identity=tuple(sorted(bindings.items()))
        # Focus changes/rebinding while held must not trigger an accidental toggle.
        if not focused or not self.focused or identity!=self.bindings:
            self.previous=set(down)
            self.focused=focused
            self.bindings=identity
            return []
        rising=set(down)-self.previous
        self.previous=set(down)
        return [module for module,key in bindings.items() if key and key in rising]


class WindowsKeys:
    def __init__(self):
        self.user=c.WinDLL('user32',use_last_error=True)
        self.user.GetForegroundWindow.restype=w.HWND
        self.user.GetWindowThreadProcessId.argtypes=[w.HWND,c.POINTER(w.DWORD)]
        self.user.GetAsyncKeyState.argtypes=[c.c_int]
        self.user.GetAsyncKeyState.restype=c.c_short

    def sample(self, keys, game_pid):
        pid=w.DWORD()
        self.user.GetWindowThreadProcessId(self.user.GetForegroundWindow(),c.byref(pid))
        focused=pid.value==game_pid and bool(game_pid)
        return {key for key in keys if key and self.user.GetAsyncKeyState(key)&0x8000},focused
