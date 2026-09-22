"""Recovered mock_bootstrap.py; original Windows startup behavior retained.

Only added parameter: asset_dir permits source and frozen builds to share assets.
Normal startup can request UAC and terminate Drip.exe/port owners, as originally.
"""
import ctypes
import os
import subprocess
import sys
import time

CREATE_NO_WINDOW = 0x08000000


def _log(msg):
    try:
        print('[boot] %s' % msg, flush=True)
    except Exception:
        pass


def _frozen():
    return bool(getattr(sys, 'frozen', False))


def _exe_dir():
    return os.path.dirname(os.path.abspath(sys.executable if _frozen() else __file__))


def _asset_dir():
    if _frozen():
        return getattr(sys, '_MEIPASS', _exe_dir())
    return os.path.dirname(os.path.abspath(__file__))


def _run(args, timeout=25):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              creationflags=CREATE_NO_WINDOW, timeout=timeout)
    except Exception:
        return None


def _copy_if_needed(src, dst):
    try:
        if os.path.isfile(dst) and os.path.getsize(dst) == os.path.getsize(src):
            return False
    except OSError:
        pass
    parent = os.path.dirname(dst)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = dst + '.part'
    with open(src, 'rb') as fsrc, open(tmp, 'wb') as fdst:
        while True:
            chunk = fsrc.read(1048576)
            if not chunk:
                break
            fdst.write(chunk)
    os.replace(tmp, dst)
    return True


def _materialise(assets, data, items):
    written = 0
    for item in items:
        src = os.path.join(assets, item)
        dst = os.path.join(data, item)
        if os.path.isdir(src):
            for root, _dirs, files in os.walk(src):
                rel = os.path.relpath(root, src)
                outdir = dst if rel == '.' else os.path.join(dst, rel)
                for name in files:
                    if _copy_if_needed(os.path.join(root, name), os.path.join(outdir, name)):
                        written += 1
        elif os.path.isfile(src):
            if _copy_if_needed(src, dst):
                written += 1
    return written


def _writable(path):
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, '.write_probe')
        with open(probe, 'wb') as fh:
            fh.write(b'x')
        os.remove(probe)
        return True
    except Exception:
        return False


def _listeners():
    res = _run(['netstat', '-ano', '-p', 'tcp'])
    rows = []
    if not res or not res.stdout:
        return rows
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != 'TCP':
            continue
        local, state = parts[1], parts[3].upper()
        try:
            pid = int(parts[4])
        except ValueError:
            continue
        if ':' not in local:
            continue
        rows.append((local.rsplit(':', 1)[1], pid, state))
    return rows


def _taskkill(pid):
    return _run(['taskkill', '/F', '/T', '/PID', str(pid)], timeout=20)


def free_port(port, tries=4):
    port = str(port)
    mine = os.getpid()
    for attempt in range(tries):
        targets = [(pid, state) for p, pid, state in _listeners() if p == port and pid not in (0, 4, mine)]
        if not targets:
            if attempt == 0:
                _log('port %s is free' % port)
            return True
        for pid, state in targets:
            _log('port %s held by pid %d (%s) -- killing it' % (port, pid, state))
            _taskkill(pid)
        time.sleep(0.6)
    left = [pid for p, pid, _s in _listeners() if p == port and pid not in (0, 4, mine)]
    if left:
        _log('WARNING: port %s still held by pid(s) %s' % (port, left))
        return False
    return True


def kill_image(image, keep_pid=None):
    res = _run(['tasklist', '/FI', 'IMAGENAME eq %s' % image, '/FO', 'CSV', '/NH'])
    if not res or not res.stdout:
        return 0
    killed = 0
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line.startswith('"'):
            continue
        fields = [f.strip('"') for f in line.split(',')]
        if len(fields) < 2:
            continue
        try:
            pid = int(fields[1])
        except ValueError:
            continue
        if pid in (0, 4) or (keep_pid is not None and pid == keep_pid):
            continue
        _taskkill(pid)
        killed += 1
    return killed


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True


def ensure_admin():
    if is_admin():
        return True
    _log('NOT running as Administrator')
    if os.environ.get('MOCK_NO_ELEVATE'):
        return False
    if _frozen():
        try:
            args = ' '.join('"%s"' % a for a in sys.argv[1:])
            rc = ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, args, None, 1)
            if int(rc) > 32:
                _log('re-launched elevated -- this window will close')
                return None
            _log('elevation request refused (ShellExecuteW -> %s)' % rc)
        except Exception as exc:
            _log('elevation failed: %s' % exc)
    return False


def install_excepthook():
    def _hook(exc_type, exc, tb):
        import traceback
        traceback.print_exception(exc_type, exc, tb)
        sys.stderr.flush()
        try:
            input('\n[!] fatal error -- press Enter to close...')
        except Exception:
            pass
    sys.excepthook = _hook


def bootstrap(tag, items, ports=(1420, 8765), kill_images=('Drip.exe',), *, asset_dir=None):
    install_excepthook()
    _log('=' * 64)
    _log('%s   (frozen=%s)' % (tag, _frozen()))
    elevated = ensure_admin()
    if elevated is None:
        os._exit(0)
    if not elevated:
        _log('WARNING: no Administrator rights -- frida injection will probably fail')
    base = _exe_dir()
    assets = asset_dir if asset_dir is not None else _asset_dir()
    candidates = []
    if os.environ.get('MOCK_DATA_DIR'):
        candidates.append(os.environ['MOCK_DATA_DIR'])
    try:
        if all(os.path.exists(os.path.join(base, it)) for it in items):
            candidates.append(base)
    except Exception:
        pass
    candidates.append(os.path.join(base, tag + '_data'))
    candidates.append(os.path.join(os.environ.get('LOCALAPPDATA', base), tag + '_data'))
    data = next((cand for cand in candidates if _writable(cand)), None)
    if data is None:
        _log('FATAL: no writable data directory found')
        raise SystemExit(1)
    _log('program dir : %s' % base)
    _log('asset dir   : %s' % assets)
    _log('data dir    : %s' % data)
    written = _materialise(assets, data, items)
    _log('assets ready (%d file(s) written/refreshed)' % written)
    drip = os.path.join(data, 'Drip.exe')
    external = os.path.join(base, 'Drip.exe')
    try:
        if (os.path.isfile(external) and os.path.abspath(external) != os.path.abspath(drip)
                and os.path.getsize(external) > 0):
            drip = external
            _log('using external Drip.exe sitting next to this program')
    except OSError:
        pass
    if not os.path.isfile(drip):
        _log('WARNING: Drip.exe not found (looked in %s)' % data)
    else:
        _log('target exe  : %s (%d bytes)' % (drip, os.path.getsize(drip)))
    try:
        os.chdir(data)
    except Exception:
        pass
    for image in kill_images:
        n = kill_image(image)
        if n:
            _log('terminated %d running %s process(es)' % (n, image))
    for port in ports:
        free_port(port)
    _log('bootstrap complete')
    _log('=' * 64)
    return dict(data_dir=data, drip_exe=drip, base_dir=base, asset_dir=assets)
