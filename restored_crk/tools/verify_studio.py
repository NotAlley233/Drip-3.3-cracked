"""Exercise the actual packaged application over loopback in isolated demo data."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def verify(executable):
    events = []
    def request(origin, method='GET', path='/api/state', body=None, token=None, expected=200, headers=None):
        extra = {'Content-Type': 'application/json'} if body is not None else {}
        if token:
            extra['X-Panel-Token'] = token
        extra.update(headers or {})
        req = urllib.request.Request(origin + path, method=method,
              data=json.dumps(body).encode() if body is not None else None, headers=extra)
        try:
            response = urllib.request.urlopen(req, timeout=4)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read()
            assert response.status == expected, (path, response.status, data)
            events.append({'method': method, 'path': path, 'status': response.status})
            return json.loads(data) if response.headers['Content-Type'].startswith('application/json') else data

    with tempfile.TemporaryDirectory(prefix='driplite-studio-') as folder:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        origin = 'http://127.0.0.1:' + str(port)
        command = [str(executable), '--demo', '--no-browser', '--data', folder, '--port', str(port)]
        def start():
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                for _ in range(200):
                    if process.poll() is not None:
                        raise RuntimeError('Application exited early: ' + str(process.communicate()))
                    try:
                        state = request(origin)
                        assert state['product'] == 'driplite-studio' and state['demo']
                        return process, state
                    except (OSError, urllib.error.URLError):
                        time.sleep(0.1)
                raise RuntimeError('Panel did not become ready')
            except BaseException:
                process.terminate()
                process.communicate(timeout=10)
                raise
        def stop(process, state):
            request(origin, 'POST', '/api/stop', {'revision': state['revision']}, state['token'])
            out, err = process.communicate(timeout=15)
            events.append({'command': command, 'stdout': out, 'stderr': err, 'exit_status': process.returncode})
            assert process.returncode == 0 and not err
        process, state = start()
        try:
            assert len(state['catalog']['modules']) == 44
            assert sum(len(m['fields']) for m in state['catalog']['modules']) == 99
            assert state['values']['auto-clicker.cps'] == 25
            assert b'Driplite Studio' in request(origin, path='/')
            assert b'config_editor' not in request(origin, path='/app.js')
            assert request(origin, path='/style.css')
            duplicate = subprocess.run(command, capture_output=True, text=True, timeout=20)
            events.append({'label': 'singleton', 'command': command, 'stdout': duplicate.stdout,
                           'stderr': duplicate.stderr, 'exit_status': duplicate.returncode})
            assert duplicate.returncode == 0
            request(origin, 'POST', '/api/patch', {'revision': 0, 'values': {'auto-clicker.cps': 30}}, expected=403)
            request(origin, 'POST', '/api/patch', {'revision': 0, 'values': {'auto-clicker.cps': 30}},
                    state['token'], expected=403, headers={'Origin': 'http://example.invalid'})
            state = request(origin, 'POST', '/api/patch', {'revision': 0, 'values': {'auto-clicker.cps': 30}}, state['token'])
            assert state['values']['auto-clicker.cps'] == 30
            request(origin, 'POST', '/api/reset', {'revision': 0}, state['token'], expected=400)
            state = request(origin, 'POST', '/api/profile-save', {'revision': 1, 'name': 'integration'}, state['token'])
            state = request(origin, 'POST', '/api/undo', {'revision': 1}, state['token'])
            assert state['values']['auto-clicker.cps'] == 25
            events.append({'BASELINE': 25, 'MODIFIED': 30, 'ROLLBACK': 25})
            state = request(origin, 'POST', '/api/profile-load', {'revision': 2, 'name': 'integration'}, state['token'])
            assert state['values']['auto-clicker.cps'] == 30
            stop(process, state)
            process, state = start()
            assert state['values']['auto-clicker.cps'] == 30 and 'integration' in state['profiles']
            state = request(origin, 'POST', '/api/reset', {'revision': state['revision']}, state['token'])
            assert state['values']['auto-clicker.cps'] == 25
            stop(process, state)
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=15)
    result = {'passed': True, 'native_execution': False, 'events': events,
              'checks': ['packaged HTTP UI', '44 modules/99 fields', 'singleton', 'request validation',
                         '25 -> 30 -> 25', 'named profiles', 'restart persistence', 'graceful shutdown']}
    output = ROOT / 'evidence/studio_verification.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'passed': True, 'checks': result['checks'], 'record': str(output)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, default=ROOT / 'dist/Driplite-Studio.exe')
    args = parser.parse_args()
    verify(args.exe.resolve())
