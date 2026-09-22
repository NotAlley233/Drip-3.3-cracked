"""Recovered Python launcher logic from entry_nice/entry_321 (CPython 3.13).

Function names and protocol branches follow the original bytecode. Startup is
explicit in main(); captured constants are extracted to untracked session.json.
The native Drip.exe and packed_dll.bin are original binary dependencies.
"""
import binascii
import ctypes
import http.server as _hs
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time

from nacl.bindings import (
    crypto_scalarmult, crypto_scalarmult_base,
    crypto_secretstream_xchacha20poly1305_init_pull as pull_init,
    crypto_secretstream_xchacha20poly1305_pull as ss_pull,
    crypto_secretstream_xchacha20poly1305_init_push as push_init,
    crypto_secretstream_xchacha20poly1305_push as ss_push,
    crypto_secretstream_xchacha20poly1305_state as ss_state,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL as TF,
)
from nacl.hash import blake2b
from nacl.encoding import RawEncoder

H = lambda b: binascii.hexlify(b).decode()
U = binascii.unhexlify
STATE = {'result': '?', 'wall2': False, 'reached_dll': False}
WIRE_HTTP_PORT = 8765


def bl(d, sz=64, key=b''):
    return blake2b(d, digest_size=sz, key=key, encoder=RawEncoder)


def L(s):
    print(s, flush=True)
    LOG.write(str(s) + '\n')
    LOG.flush()


class _WireBridge(_hs.BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        pass

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path == '/wire/config_0x21':
            try:
                with open(WIRE_CFG_PATH, 'rb') as stream:
                    data = stream.read()
            except Exception:
                self.send_response(404)
                self._cors()
                self.end_headers()
                return
            self.send_response(200)
            self._cors()
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self._cors()
            self.end_headers()

    def do_POST(self):
        if self.path == '/wire/config_0x21':
            try:
                ln = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(ln)
            except Exception:
                self.send_response(400)
                self._cors()
                self.end_headers()
                return
            if len(body) != 657 or body[0] != 0x21:
                self.send_response(400)
                self._cors()
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(('rejected: expected 657 bytes starting with 0x21, got %d bytes starting with 0x%02x' %
                                  (len(body), body[0] if body else -1)).encode())
                return
            with open(WIRE_CFG_PATH, 'wb') as stream:
                stream.write(body)
            L('[wire-http] config_0x21.bin updated via webpage (%d bytes) -- next poll will send this' % len(body))
            self.send_response(200)
            self._cors()
            self.end_headers()
        else:
            self.send_response(404)
            self._cors()
            self.end_headers()


def start_wire_bridge():
    try:
        srv = _hs.ThreadingHTTPServer(('127.0.0.1', WIRE_HTTP_PORT), _WireBridge)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        L('[wire-http] bridge up at http://127.0.0.1:%d (webpage reads/writes config_0x21.bin live)' % WIRE_HTTP_PORT)
    except Exception as e:
        L('[wire-http] FAILED to start bridge: %s' % e)


def recvn(c, n):
    b = b''
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            raise EOFError('closed %d/%d' % (len(b), n))
        b += d
    return b


def rframe(c):
    m = recvn(c, 2)
    assert m == b'CY', H(m)
    ln = int.from_bytes(recvn(c, 4), 'big')
    return recvn(c, ln)


def sframe(c, body):
    c.sendall(b'CY' + len(body).to_bytes(4, 'big') + body)


def handle_conn(c, peer, connN):
    c.settimeout(20)
    L('[srv] connection #%d from %s' % (connN, peer))
    try:
        s_es = crypto_scalarmult(CLIENT_SK, PK_B)
        keys = bl(s_es + CLIENT_PK + PK_B, 64)
        ck, sk = keys[:32], keys[32:]
        L('[srv] s_es=%s' % H(s_es))
        L('[srv] ck=%s sk=%s' % (H(ck), H(sk)))
        m1 = rframe(c)
        cpk, hdr, ct = m1[1:33], m1[33:57], m1[57:]
        L('[C->S msg1] client_pk=%s' % H(cpk))
        L('[srv] client_pk matches friend: %s' % (cpk == CLIENT_PK))
        L('[srv] header matches friend  : %s' % (hdr == HEADER))
        pst = ss_state()
        pull_init(pst, hdr, ck)
        pt1, _ = ss_pull(pst, ct, None)
        L('[C->S msg1 pt] %s' % H(pt1))
        L('[srv] msg1 == friend msg1: %s' % (pt1 == b'\x00e\x00' + RNG4 + b'\x00'))
        pushst = ss_state()
        shdr = push_init(pushst, sk)
        rx1 = ss_push(pushst, TOKEN + EPH_PK + AUTHFIELD, None, TF)
        sframe(c, b'\x02' + shdr + rx1)
        L('[S->C rx1] REPLAYED real auth field, waiting for msg3 ...')
        m3 = rframe(c)
        STATE['wall2'] = True
        STATE['result'] = 'WALL2_PASSED'
        pt3, _ = ss_pull(pst, m3, None)
        L('[*][*][*] WALL #2 DEFEATED: client accepted rx1 and sent msg3')
        L('[C->S msg3 pt] %s' % H(pt3))
        rx2 = ss_push(pushst, U('0401'), None, TF)
        sframe(c, rx2)
        L('[S->C rx2] sent 0401 (ACK)')
        au = rframe(c)
        pta, _ = ss_pull(pst, au, None)
        L('[C->S auth/HWID] len=%d' % len(pta))
        L('[C->S auth hex] %s' % H(pta))
        L('[C->S auth asc] %s' % ''.join(chr(x) if 32 <= x < 127 else '.' for x in pta))
        rx3 = ss_push(pushst, U('0401'), None, TF)
        sframe(c, rx3)
        L('[S->C rx3] sent 0401 (success verdict) -- client should now expect the DLL')
        STATE['reached_dll'] = True
        STATE['result'] = 'REACHED_DLL_STAGE'
        c.settimeout(6)
        try:
            req = rframe(c)
            ptr, _ = ss_pull(pst, req, None)
            L('[C->S post-verdict req] frame=%dB plaintext=%dB %s' % (len(req), len(ptr), H(ptr)))
        except Exception as e:
            L('[srv] no req frame (%s)' % e)
        PROBE = os.environ.get('PROBE', '')
        if os.environ.get('NODLL'):
            L('[srv] NODLL: sending nothing, just listening to Drip download request')
        elif PROBE:
            lo, hi = (int(x, 0) for x in PROBE.split('-')) if '-' in PROBE else (0, 64)
            L('[srv] PROBE types %#x..%#x' % (lo, hi))
            for t in range(lo, hi + 1):
                body = bytes([t])
                sframe(c, ss_push(pushst, body, None, TF))
                time.sleep(0.25)
            L('[srv] probes sent, collecting log ...')
        else:
            DLL_PATH = os.environ.get('DLL_PATH', os.path.join(HERE, SESSION_DIR, 'packed_dll.bin'))
            TRUNC = int(os.environ.get('DLL_TRUNC', '0'))
            PFX = bytes.fromhex(os.environ.get('DLL_PFX', '20'))
            with open(DLL_PATH, 'rb') as stream:
                dll = stream.read()
            if TRUNC > 0:
                dll = dll[:TRUNC] if len(dll) >= TRUNC else dll + b'\x00' * (TRUNC - len(dll))
            dll = PFX + dll
            L('[srv] DLL src=%s filesize=%d pfx=%s sending=%d' %
              (os.path.basename(DLL_PATH), os.path.getsize(DLL_PATH), PFX.hex(), len(dll)))
            dctf = ss_push(pushst, dll, None, TF)
            body = b'CY' + len(dctf).to_bytes(4, 'big') + dctf
            CHUNK, PACE_S = 262144, 0.05
            for i in range(0, len(body), CHUNK):
                c.sendall(body[i:i + CHUNK])
                if i + CHUNK < len(body):
                    time.sleep(PACE_S)
            L('[S->C DLL] pushed one frame body=%d bytes (paced, ~%.0fs)' % (len(dctf), len(body) / CHUNK * PACE_S))
        c.settimeout(5)
        buf = b''
        last_activity = time.time()
        IDLE_GIVEUP = 3600
        while True:
            try:
                try:
                    chunk = c.recv(65536)
                except socket.timeout:
                    if time.time() - last_activity > IDLE_GIVEUP:
                        L('[srv] no traffic for %ds, giving up' % IDLE_GIVEUP)
                        break
                    continue
                if not chunk:
                    L('[srv] client closed conn')
                    break
                last_activity = time.time()
                buf += chunk
                while len(buf) >= 6 and buf[:2] == b'CY':
                    ln = int.from_bytes(buf[2:6], 'big')
                    if len(buf) < 6 + ln:
                        break
                    fr, buf = buf[6:6 + ln], buf[6 + ln:]
                    try:
                        ptc, tg = ss_pull(pst, fr, None)
                        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in ptc[:64])
                        L('[C->S post-DLL] frame=%dB pt=%dB tag=%d type=%#x hex=%s asc=%s' %
                          (ln, len(ptc), tg, ptc[0] if ptc else -1, H(ptc[:48]), asc))
                        fd = os.path.join(HERE, 'replay_frames')
                        os.makedirs(fd, exist_ok=True)
                        STATE['nf'] = STATE.get('nf', 0) + 1
                        with open(os.path.join(fd, 'f%02d_t%02x_%dB.bin' %
                                  (STATE['nf'], ptc[0] if ptc else 0, len(ptc))), 'wb') as stream:
                            stream.write(ptc)
                        if ptc and ptc[0] == 0x22:
                            s321 = os.path.join(HERE, SESSION_DIR)
                            for cf in ('config_0x21.bin', 'config_0x30.bin'):
                                cp = os.environ.get('CFG_%s' % cf, os.path.join(s321, cf))
                                if os.path.isfile(cp):
                                    with open(cp, 'rb') as stream:
                                        body = stream.read()
                                    sframe(c, ss_push(pushst, body, None, TF))
                                    L('[S->C config] sent %s type=%#x len=%d' % (cf, body[0], len(body)))
                                else:
                                    L('[S->C config] MISSING %s' % cp)
                        elif ptc and ptc[0] == 0x10:
                            s321 = os.path.join(HERE, SESSION_DIR)
                            cp = os.environ.get('CFG_config_0x21.bin', os.path.join(s321, 'config_0x21.bin'))
                            if os.path.isfile(cp):
                                with open(cp, 'rb') as stream:
                                    body = stream.read()
                                sframe(c, ss_push(pushst, body, None, TF))
                                L('[S->C config-poll] answered 0x10 poll with config_0x21.bin len=%d' % len(body))
                            else:
                                L('[S->C config-poll] MISSING %s' % cp)
                    except Exception as e:
                        L('[C->S post-DLL] frame=%dB DECRYPT-FAIL %s' % (ln, e))
                if buf and buf[:2] != b'CY':
                    L('[srv] non-CY tail %dB %s' % (len(buf), H(buf[:32])))
                    buf = b''
            except Exception as e:
                L('[srv] recv done (%s)' % e)
                break
    except Exception as e:
        STATE['result'] = 'err(%s: %s)' % (type(e).__name__, e)
        L('[srv] ERROR %s' % e)
    finally:
        try:
            c.close()
        except Exception:
            pass


def server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 1420))
    s.listen(5)
    L('[srv] listen 127.0.0.1:1420 (replay, real pk_B) -- will accept MULTIPLE reconnects')
    connN = 0
    while True:
        try:
            c, peer = s.accept()
        except Exception as e:
            L('[srv] accept() failed, stopping: %s' % e)
            break
        connN += 1
        try:
            handle_conn(c, peer, connN)
        except Exception as e:
            L('[srv] connection #%d ended with error: %s' % (connN, e))
        L('[srv] connection #%d closed -- still listening for reconnects' % connN)


def find_mc():
    u = ctypes.windll.user32
    for cls in ('LWJGL', 'GLFW30', 'GLFW'):
        hwnd = u.FindWindowW(cls, None)
        if hwnd:
            pid = ctypes.c_ulong(0)
            u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            return pid.value, cls
    return None, None


def om(m, d):
    if m.get('type') != 'send':
        L('[frida-err] ' + str(m))
        return
    p = m['payload']
    t = p.get('t')
    if t == 'rng':
        L('[rng] len=%d %s%s' % (p['len'], p['hex'][:48], '  <=FORCED ' + p['forced'] if p.get('forced') else ''))
    else:
        L('[frida] ' + p.get('m', ''))


def _out(pid_, fd, data):
    try:
        t = data.decode('utf-8', 'replace')
    except Exception:
        t = repr(data)
    for line in t.splitlines():
        if line.strip():
            L('[client] ' + line.strip())


def main(asset_dir, timeout=60, stop_requested=lambda: False):
    """Original top-level startup, made explicit for import/build/self-test."""
    import frida
    import mock_bootstrap as _mb
    global HERE, LOG, WIRE_CFG_PATH, SESSION_DIR
    global PK_B, CLIENT_SK, HEADER, RNG4, TOKEN, EPH_PK, AUTHFIELD, CLIENT_PK
    asset_dir = Path(asset_dir).resolve()
    manifest = json.loads((asset_dir / 'manifest.json').read_text(encoding='utf-8'))
    values = json.loads((asset_dir / 'session.json').read_text(encoding='utf-8'))
    PK_B, CLIENT_SK, HEADER, RNG4, TOKEN, EPH_PK, AUTHFIELD = (
        bytes.fromhex(values[key]) for key in
        ('PK_B', 'CLIENT_SK', 'HEADER', 'RNG4', 'TOKEN', 'EPH_PK', 'AUTHFIELD'))
    CLIENT_PK = crypto_scalarmult_base(CLIENT_SK)
    assert CLIENT_PK == bytes.fromhex(values['CLIENT_PK_EXPECTED'])
    SESSION_DIR = manifest['session_dir']
    _BOOT = _mb.bootstrap(manifest['tag'], [manifest['script'], SESSION_DIR, 'Drip.exe'],
                          asset_dir=str(asset_dir))
    HERE = _BOOT['data_dir']
    LOG = open(os.path.join(HERE, 'replay.log'), 'w', encoding='utf-8')
    WIRE_CFG_PATH = os.path.join(HERE, SESSION_DIR, 'config_0x21.bin')
    STATE.clear()
    STATE.update(result='?', wall2=False, reached_dll=False)
    start_wire_bridge()
    mc, cls = find_mc()
    L('[pre] MC %s' % ('class=%s pid=%d' % (cls, mc) if mc else 'NO WINDOW - open Minecraft first!'))
    th = threading.Thread(target=server, daemon=True)
    th.start()
    time.sleep(0.4)
    js = Path(HERE, manifest['script']).read_text(encoding='utf-8')
    js = js.replace('__CLIENT_SK__', H(CLIENT_SK)).replace('__HEADER__', H(HEADER)).replace('__RNG4__', H(RNG4))
    dev = frida.get_local_device()
    pid = dev.spawn([_BOOT['drip_exe']], stdio='pipe')
    dev.on('output', _out)
    sess = dev.attach(pid)
    sc = sess.create_script(js)
    sc.on('message', om)
    sc.load()
    dev.resume(pid)
    L('[*] spawned Drip pid=%d' % pid)
    deadline = time.monotonic() + timeout
    while th.is_alive() and time.monotonic() < deadline and not stop_requested():
        th.join(timeout=min(0.2, max(0, deadline - time.monotonic())))
    time.sleep(1)
    L('RESULT=%s  wall2=%s reached_dll=%s' % (STATE['result'], STATE['wall2'], STATE['reached_dll']))
    if os.environ.get('MOCK_AUTOCLOSE') or stop_requested():
        L('[*] MOCK_AUTOCLOSE set -- shutting down cleanly.')
        try:
            dev.kill(pid)
        except Exception:
            pass
        LOG.close()
        return
    if th.is_alive():
        L('[*] still running -- mock stays up so the injected cheat keeps working.')
        L('[*] go play in Minecraft now. Press Ctrl+C HERE when you are done testing.')
        try:
            while th.is_alive() and not stop_requested():
                time.sleep(1)
        except KeyboardInterrupt:
            L('[*] Ctrl+C received -- stopping.')
    else:
        L('[*] server thread already ended (%s).' % STATE.get('result'))
    try:
        dev.kill(pid)
    except Exception:
        pass
    LOG.close()
