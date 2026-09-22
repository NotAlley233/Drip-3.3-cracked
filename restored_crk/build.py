"""Build the recovered .py sources; never nest the original outer executable."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from tools.prepare_assets import prepare, verify_prepared, ORIGINALS

ROOT = Path(__file__).resolve().parent


def build(variant, input_dir, refresh_assets=False):
    variants = list(ORIGINALS) if variant == 'all' else [variant]
    resources = []
    for preset in variants:
        if not refresh_assets and (ROOT / 'assets' / preset / 'manifest.json').is_file():
            assets = verify_prepared(preset)
        else:
            assets = prepare(preset, input_dir)
        resources += ['--add-data', str(assets) + ';assets/' + preset]
    work = ROOT / 'build' / variant / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    work.mkdir(parents=True, exist_ok=True)
    default = work / 'default.json'
    default.write_text(json.dumps({'variant': variants[0], 'available': variants}), encoding='utf-8')
    name = 'Driplite-Studio' + ('' if variant == 'all' else '-' + variant)
    command = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--console',
               '--name', name, '--distpath', str(ROOT / 'dist'),
               '--workpath', str(work / 'work'), '--specpath', str(work),
               '--paths', str(ROOT / 'src'), '--collect-all', 'frida', '--collect-all', 'nacl',
               '--hidden-import', '_cffi_backend',
               *resources, '--add-data', str(ROOT / 'src/panel') + ';panel',
               '--add-data', str(default) + ';assets', str(ROOT / 'src' / 'launcher.py')]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace')
    record = {'command': command, 'exit_status': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
              'environment': {'python_version': sys.version, 'PYTHONPATH': os.environ.get('PYTHONPATH', '')},
              'source_hashes': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in sorted((ROOT / 'src').rglob('*')) if p.is_file() and '__pycache__' not in p.parts}}
    (work / 'command_execution.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
    if result.returncode:
        print(result.stderr, file=sys.stderr)
        raise SystemExit(result.returncode)
    output = ROOT / 'dist' / (name + '.exe')
    for preset in variants:
        check_command = [str(output), '--self-test', '--variant', preset]
        check = subprocess.run(check_command, cwd=work, capture_output=True, text=True, timeout=90)
        verification = {'command': check_command, 'exit_status': check.returncode,
                        'stdout': check.stdout, 'stderr': check.stderr,
                        'sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'size': output.stat().st_size}
        (work / ('self_test_' + preset + '.json')).write_text(json.dumps(verification, indent=2), encoding='utf-8')
        print(check.stdout, end='')
        if check.returncode:
            print(check.stderr, file=sys.stderr)
            raise SystemExit(check.returncode)
    print('BUILT ' + str(output))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--variant', choices=['nice', '123', 'all'], default='all')
    parser.add_argument('--input-dir', type=Path, default=ROOT.parent)
    parser.add_argument('--refresh-assets', action='store_true', help='Re-extract assets from original EXEs')
    args = parser.parse_args()
    build(args.variant, args.input_dir, args.refresh_assets)
