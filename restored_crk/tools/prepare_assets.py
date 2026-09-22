"""Extract original resources; never import or execute the input EXEs/code."""
import argparse
import hashlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
from PyInstaller.archive.readers import CArchiveReader
from xdis.unmarshal import load_code
from xdis.bytecode import get_instructions_bytes
from xdis.op_imports import get_opcode_module
from xdis.version_info import PythonImplementation

ORIGINALS = {
    'nice': ('Driplite 3.3cracked with nice cfg.exe', '56908706c64f4a5c80b6d84dbb885bab6ab0e253b5f228c41870424fe6189bad', 'entry_nice', 'session_nice', 'mock_replay_nice.js', 'MockReplayNice'),
    '123': ('Driplite 3.3cracked with 123 cfg.exe', 'aee4852fdd1ff6203aeec44a0f560b0eb316f842bbc7a57dd5e1aacb26d30f27', 'entry_321', 'session321', 'mock_replay_321.js', 'MockReplay321'),
}


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def session_values(blob):
    code = load_code(io.BytesIO(blob), 3571, code_objects={})
    opc = get_opcode_module((3, 13), PythonImplementation.CPython)
    wanted = {'PK_B', 'CLIENT_SK', 'HEADER', 'RNG4', 'TOKEN', 'EPH_PK', 'AUTHFIELD'}
    found = {}
    last_constant = None
    public_key_stored = False
    for instruction in get_instructions_bytes(code, opc):
        if instruction.opname == 'LOAD_CONST':
            last_constant = instruction.argval
        elif instruction.opname == 'STORE_NAME' and instruction.argval in wanted:
            value = last_constant
            found[instruction.argval] = value.hex() if isinstance(value, bytes) else value
        elif instruction.opname == 'STORE_NAME' and instruction.argval == 'CLIENT_PK':
            public_key_stored = True
        elif public_key_stored and instruction.opname == 'COMPARE_OP':
            found['CLIENT_PK_EXPECTED'] = last_constant
            public_key_stored = False
    if set(found) != wanted | {'CLIENT_PK_EXPECTED'}:
        raise ValueError('Original session constants could not be recovered')
    for key, value in found.items():
        if len(bytes.fromhex(value)) != (24 if key == 'HEADER' else 32):
            raise ValueError('Unexpected session constant length: ' + key)
    return found


def prepare(variant, input_dir=REPO, output_dir=ROOT / 'assets'):
    name, expected, entry, session, script, tag = ORIGINALS[variant]
    original = Path(input_dir) / name
    actual = digest(original.read_bytes())
    if actual != expected:
        raise ValueError('Original EXE hash mismatch: ' + str(original))
    archive = CArchiveReader(str(original))
    destination = Path(output_dir) / variant
    destination.mkdir(parents=True, exist_ok=True)
    members = ['Drip.exe', script] + [session + '/' + leaf for leaf in
                ('packed_dll.bin', 'config_0x21.bin', 'config_0x30.bin')]
    toc = {name.replace('\\', '/'): name for name in archive.toc}
    records = []
    for name in members:
        blob = archive.extract(toc[name])
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        records.append({'path': name, 'sha256': digest(blob), 'size': len(blob)})
    values = session_values(archive.extract(entry))
    (destination / 'session.json').write_text(json.dumps(values, indent=2) + '\n', encoding='utf-8')
    records.append({'path': 'session.json', 'sha256': digest((destination / 'session.json').read_bytes()), 'size': (destination / 'session.json').stat().st_size})
    manifest = {'variant': variant, 'tag': tag, 'session_dir': session,
                'script': script, 'original_name': original.name,
                'original_sha256': actual, 'assets': records}
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'variant': variant, 'original_verified': True, 'asset_count': len(records)}))
    return destination


def verify_prepared(variant, output_dir=ROOT / 'assets'):
    destination = Path(output_dir) / variant
    manifest = json.loads((destination / 'manifest.json').read_text(encoding='utf-8'))
    if manifest['variant'] != variant or manifest['original_sha256'] != ORIGINALS[variant][1]:
        raise ValueError('Prepared assets have unexpected provenance')
    for entry in manifest['assets']:
        if digest((destination / entry['path']).read_bytes()) != entry['sha256']:
            raise ValueError('Prepared asset hash mismatch: ' + entry['path'])
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--variant', choices=['nice', '123', 'all'], default='all')
    parser.add_argument('--input-dir', type=Path, default=REPO)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'assets')
    args = parser.parse_args()
    for variant in ORIGINALS if args.variant == 'all' else [args.variant]:
        prepare(variant, args.input_dir, args.output_dir)
