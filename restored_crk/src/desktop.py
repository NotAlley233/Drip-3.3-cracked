"""One application: restored launcher, local parameter UI and saved profiles."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
import webbrowser

DEFAULT_DATA = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'DriplitePanel'


def data_directory(base, variant):
    # Keep existing nice-preset profiles in their established location.
    return Path(base) if variant == 'nice' else Path(base) / variant


def child_command(variant, stop_file):
    prefix = [sys.executable] if getattr(sys, 'frozen', False) else [sys.executable, str(Path(__file__).with_name('launcher.py'))]
    return prefix + ['--inject-only', '--variant', variant, '--stop-file', str(stop_file)]


def existing(port):
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d/api/state' % port, timeout=1) as response:
            return json.load(response).get('product') == 'driplite-studio'
    except Exception:
        return False


def select_port(preferred):
    for port in range(preferred, min(preferred + 20, 65536)):
        with socket.socket() as listener:
            try:
                listener.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port
    raise RuntimeError('No local panel port available')


def injector_worker(variant, data, stop):
    import frida
    from runtime_discovery import process_image
    from config_store import atomic_json
    from launcher import resources
    folder, manifest = resources(variant)
    expected = next(a['sha256'] for a in manifest['assets'] if a['path'] == 'Drip.exe')
    child = None
    attempted = set()
    stop_file = data / 'launcher.stop'
    output = None
    try:
        while not stop.wait(2):
            try:
                processes = frida.get_local_device().enumerate_processes()
                games = {p.pid for p in processes if p.name.lower() == 'javaw.exe'}
                attempted.intersection_update(games)
                if not games or (child is not None and child.poll() is None):
                    continue
                loader_exists = False
                for process in processes:
                    if process.name.lower() == 'drip.exe':
                        image = process_image(process.pid)
                        if image and hashlib.sha256(Path(image).read_bytes()).hexdigest() == expected:
                            loader_exists = True
                if loader_exists or games.issubset(attempted):
                    continue
                stop_file.unlink(missing_ok=True)
                command = child_command(variant, stop_file)
                environment = os.environ.copy()
                environment['MOCK_DATA_DIR'] = str(data / 'launcher')
                if output:
                    output.close()
                output = (data / 'launcher.log').open('ab')
                child = subprocess.Popen(command, cwd=data, env=environment,
                                         stdout=output, stderr=output, creationflags=0x08000000)
                attempted.update(games)
                atomic_json(data / 'launcher-process.json', {'command': command, 'pid': child.pid,
                            'variant': variant, 'game_pids': sorted(games), 'started': time.time()})
            except Exception:
                (data / 'launcher-error.txt').write_text(traceback.format_exc(), encoding='utf-8')
    finally:
        if child is not None and child.poll() is None:
            stop_file.touch()
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                child.terminate()
                child.wait(timeout=5)
        if output:
            output.close()


def run(variant, *, demo=False, data=None, port=8770, no_browser=False, no_inject=False):
    if not 1 <= port <= 65535:
        raise ValueError('Port must be between 1 and 65535')
    data = data_directory(data or DEFAULT_DATA, variant).resolve()
    data.mkdir(parents=True, exist_ok=True)
    if not demo and not ctypes.windll.shell32.IsUserAnAdmin():
        args = sys.argv[1:] if getattr(sys, 'frozen', False) else [str(Path(__file__).with_name('launcher.py')), *sys.argv[1:]]
        result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable,
                                                    subprocess.list2cmdline(args), str(data), 0)
        if result <= 32:
            raise RuntimeError('Administrator launch was cancelled or failed')
        return
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    kernel.CreateMutexW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    # Live variants share native ports; only one integrated live instance at a time.
    mode = 'demo' if demo else 'live'
    suffix = hashlib.sha256(str(data).encode()).hexdigest()[:12] if demo else 'live'
    mutex = kernel.CreateMutexW(None, False, 'Local\\DripliteStudio-' + suffix)
    if not mutex:
        raise ctypes.WinError(ctypes.get_last_error())
    duplicate = ctypes.get_last_error() == 183
    stop = threading.Event()
    worker = None
    try:
        if duplicate:
            # Open whichever live preset owns the singleton, including another preset.
            candidates = [data / mode / 'server.json', DEFAULT_DATA / mode / 'server.json',
                          DEFAULT_DATA / '123' / mode / 'server.json']
            for candidate in candidates:
                if candidate.is_file():
                    url = json.loads(candidate.read_text())['url']
                    if existing(int(url.rsplit(':', 1)[1])):
                        if not no_browser:
                            webbrowser.open(url)
                        return
            raise RuntimeError('Driplite Studio is already starting; wait for its panel')
        selected = select_port(port)
        if not demo and not no_inject:
            worker = threading.Thread(target=injector_worker, args=(variant, data, stop), daemon=True)
            worker.start()
        from panel_server import main as serve
        args = ['--port', str(selected), '--data', str(data), '--preset', variant]
        if demo:
            args.append('--demo')
        if not no_browser:
            args.append('--open-browser')
        serve(args)
    finally:
        stop.set()
        if worker:
            worker.join(timeout=15)
        kernel.CloseHandle(mutex)
