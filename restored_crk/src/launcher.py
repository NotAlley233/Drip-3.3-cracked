"""Build/source entry with a side-effect-free self-test route."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile


def resources(variant):
    if getattr(sys, 'frozen', False):
        base = Path(sys._MEIPASS) / 'assets'
        if variant is None:
            variant = json.loads((base / 'default.json').read_text())['variant']
    else:
        base = Path(__file__).resolve().parents[1] / 'assets'
        variant = variant or 'nice'
    folder = base / variant
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
    for asset in manifest['assets']:
        blob = (folder / asset['path']).read_bytes()
        if hashlib.sha256(blob).hexdigest() != asset['sha256']:
            raise ValueError('Resource hash mismatch: ' + asset['path'])
    return folder, manifest


def self_test(folder, manifest):
    import frida
    import replay
    import mock_bootstrap
    import runtime_discovery
    from panel_server import Controller, CATALOG
    class MemorySocket:
        def __init__(self):
            self.data = b''
        def sendall(self, data):
            self.data += data
        def recv(self, n):
            chunk, self.data = self.data[:min(n, 3)], self.data[min(n, 3):]
            return chunk
    memory = MemorySocket()
    for body in (b'', b'\x21\x00\xff', bytes(range(256))):
        replay.sframe(memory, body)
        if replay.rframe(memory) != body:
            raise AssertionError('Frame roundtrip failed')
    values = json.loads((folder / 'session.json').read_text())
    sk = bytes.fromhex(values['CLIENT_SK'])
    if replay.crypto_scalarmult_base(sk) != bytes.fromhex(values['CLIENT_PK_EXPECTED']):
        raise AssertionError('Invalid session key')
    key = bytes(range(32))
    push, pull = replay.ss_state(), replay.ss_state()
    header = replay.push_init(push, key)
    replay.pull_init(pull, header, key)
    encrypted = replay.ss_push(push, b'restored-crk-self-test', None, replay.TF)
    if replay.ss_pull(pull, encrypted, None)[0] != b'restored-crk-self-test':
        raise AssertionError('Secretstream roundtrip failed')
    cfg = (folder / manifest['session_dir'] / 'config_0x21.bin').read_bytes()
    if len(cfg) != 657 or cfg[0] != 0x21:
        raise AssertionError('Invalid original config')
    script = (folder / manifest['script']).read_text(encoding='utf-8')
    for slot in ('CLIENT_SK', 'HEADER', 'RNG4'):
        script = script.replace('__' + slot + '__', values[slot])
    if any('__' + slot + '__' in script for slot in ('CLIENT_SK', 'HEADER', 'RNG4')):
        raise AssertionError('Unfilled script template')
    with tempfile.TemporaryDirectory(prefix='driplite-self-test-') as directory:
        control = Controller(True, directory)
        try:
            original = control.read_live()
            baseline = control.snapshot()['values']['auto-clicker.cps']
            changed = control.change('patch', {'revision': 0, 'values': {'auto-clicker.cps': 30}})
            modified = changed['values']['auto-clicker.cps']
            rolled = control.change('undo', {'revision': 1})
            rollback = rolled['values']['auto-clicker.cps']
            if (baseline, modified, rollback) != (25, 30, 25) or control.read_live() != original:
                raise AssertionError('Panel transaction failed')
            control.change('profile-save', {'revision': 2, 'name': 'self-test'})
            if control.store.load('self-test') != ({}, True):
                raise AssertionError('Panel profile roundtrip failed')
        finally:
            control.close()
    return {'passed': True, 'variant': manifest['variant'], 'assets_verified': len(manifest['assets']),
            'frame_roundtrips': 3, 'secretstream_roundtrip': True,
            'panel': {'modules': len(CATALOG['modules']), 'fields': sum(len(m['fields']) for m in CATALOG['modules']),
                      'BASELINE': baseline, 'MODIFIED': modified, 'ROLLBACK': rollback, 'profile_roundtrip': True},
            'frida': frida.__version__, 'frozen': bool(getattr(sys, 'frozen', False)),
            'native_execution': False}


def main():
    parser = argparse.ArgumentParser(description='Restored original crk launcher')
    parser.add_argument('timeout', type=float, nargs='?', default=60)
    parser.add_argument('--variant', choices=['nice', '123'])
    parser.add_argument('--self-test', action='store_true', help='Validate resources and imports without startup/injection')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--demo', action='store_true', help='Open the panel against a local copy')
    modes.add_argument('--inject-only', action='store_true', help='Run the recovered launcher without its panel')
    parser.add_argument('--no-inject', action='store_true', help='Connect the panel to an already running launcher')
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--data', type=Path)
    parser.add_argument('--port', type=int, default=8770)
    parser.add_argument('--stop-file', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    folder, manifest = resources(args.variant)
    if args.self_test:
        print(json.dumps(self_test(folder, manifest), sort_keys=True))
        return
    if args.inject_only:
        import replay
        replay.main(folder, args.timeout, stop_requested=lambda: bool(args.stop_file and args.stop_file.exists()))
    else:
        import desktop
        desktop.run(manifest['variant'], demo=args.demo, data=args.data, port=args.port,
                    no_browser=args.no_browser, no_inject=args.no_inject)


if __name__ == '__main__':
    main()
