"""Loopback-only named configuration panel; copy-on-write loader interception."""
import argparse
import ctypes as c
from ctypes import wintypes as w
from collections import deque
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import secrets
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse
from config_store import ProfileStore, atomic_json

ROOT = Path(__file__).resolve().parent
PANEL = ROOT / 'panel'
CATALOG = json.loads((PANEL / 'catalog.json').read_text(encoding='utf-8'))
FIELDS = {f['id']: f for m in CATALOG['modules'] for f in m['fields']}
FORMATS = {'bool':'<B', 'u32':'<I', 'i32':'<i', 'f32':'<f'}
DATA = Path(os.environ.get('DRIP_PANEL_DATA', str(Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'DriplitePanel')))


def validate_values(values):
    if not isinstance(values, dict) or len(values) > len(FIELDS):
        raise ValueError('Invalid field collection')
    result = {}
    for key, value in values.items():
        if key not in FIELDS:
            raise ValueError('Unknown field: ' + key)
        field = FIELDS[key]
        if isinstance(value, bool):
            if field['type'] != 'bool':
                raise ValueError('A number is required: ' + key)
            value = int(value)
        if not isinstance(value, (float, int)) or not math.isfinite(value):
            raise ValueError('Finite number required: ' + key)
        if not field['min'] <= value <= field['max']:
            raise ValueError('Outside editor range: ' + key)
        if field['type'] != 'f32' and int(value) != value:
            raise ValueError('Integer required: ' + key)
        if field.get('options') and value not in [o['value'] for o in field['options']]:
            raise ValueError('Unsupported mode: ' + key)
        packed = struct.pack(FORMATS[field['type']], value if field['type']=='f32' else int(value))
        result[key] = struct.unpack(FORMATS[field['type']], packed)[0]
    return result


def validate_pairs(values, source):
    effective = {**decode(source), **values}
    for lower, upper in CATALOG.get('ordered_pairs', []):
        if (lower in values or upper in values) and effective[lower] > effective[upper]:
            raise ValueError('Minimum must not exceed maximum: '+lower+' / '+upper)


def decode(blob):
    values = {}
    for key, field in FIELDS.items():
        value = struct.unpack_from(FORMATS[field['type']], blob, field['offset'])[0]
        values[key] = value if math.isfinite(value) else None
    return values


class Controller:
    def __init__(self, demo=False, data=None):
        self.lock = threading.RLock()
        self.mutation_lock = threading.RLock()
        self.demo = demo
        self.token = secrets.token_urlsafe(32)
        self.overrides = {}
        self.enabled = True
        self.revision = 0
        self.history = deque(maxlen=100)
        self.events = deque(maxlen=200)
        self.last_write = None
        self.error = None
        self.session = self.agent = self.handle = None
        self.count = 0
        self.closed = False
        self.data = Path(data or DATA) / ('demo' if demo else 'live')
        self.store = ProfileStore(self.data/'profiles', validate_values)
        self.run = self.data/'runs'/('panel-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        self.run.mkdir(parents=True)
        self.baseline = {'pid':None}
        self.source = (PANEL/'default.native.bin').read_bytes()
        self.original = self.source
        self.ready = demo
        self.persistence_error = None
        self.stop_event = threading.Event()
        try:
            saved = self.data/'autosave.json'
            if saved.exists():
                document = json.loads(saved.read_text(encoding='utf-8'))
                if document.get('format')!='driplite-overrides-v1' or not isinstance(document.get('enabled'),bool):
                    raise ValueError('Invalid autosave')
                self.overrides = validate_values(document['values'])
                source_values=decode(self.source)
                for key in list(self.overrides):
                    if FIELDS[key]['kind']=='key':
                        state=key.rsplit('.',1)[0]+'.enabled'
                        if state in FIELDS:self.overrides.setdefault(state,int(source_values[state]))
                validate_pairs(self.overrides, self.source)
                self.enabled = document['enabled']
        except Exception as error:
            self.persistence_error = 'Saved configuration could not be loaded: '+str(error)
        self.worker = None
        self.hotkey_worker = None
        if not demo:
            self.error = 'Waiting for injection'
            self.worker = threading.Thread(target=self.reconnect_loop, daemon=True)
            self.worker.start()
            self.hotkey_worker=threading.Thread(target=self.hotkey_loop,daemon=True)
            self.hotkey_worker.start()

    def managed_bindings(self):
        return {m['id']:int(self.overrides[m['id']+'.key']) for m in CATALOG['modules'] if m['id']+'.key' in self.overrides and m['id']+'.enabled' in FIELDS}

    def hotkey_loop(self):
        from hotkeys import WindowsKeys, KeyEdges
        keyboard,edges=WindowsKeys(),KeyEdges()
        while not self.stop_event.wait(.015):
            try:
                with self.mutation_lock:
                    bindings=self.managed_bindings()
                    down,focused=keyboard.sample(set(bindings.values()),self.baseline.get('pid'))
                    modules=edges.update(bindings,down,focused and self.ready and self.enabled and not self.error)
                    if modules:
                        live=decode(self.read_live())
                        values={m+'.enabled':1-int(self.overrides.get(m+'.enabled',live[m+'.enabled'])) for m in modules}
                        self.change('patch',{'revision':self.revision,'values':values})
            except Exception as error:
                self.events.append({'kind':'hotkey-error','message':str(error),'time':time.time()*1000})

    def wire_values(self, values):
        # Custom bindings are handled once by the foreground key dispatcher.
        # Disable the native binding in the outgoing copy to prevent double toggles.
        return {k:(0 if FIELDS[k]['kind']=='key' and k.rsplit('.',1)[0]+'.enabled' in FIELDS else v) for k,v in values.items()}

    def connect(self):
        from runtime_discovery import discover
        self.baseline, identity = discover(PANEL)
        from process_memory import kernel, read
        self.kernel, self.read = kernel, read
        self.handle = kernel.OpenProcess(0x410,False,self.baseline['pid'])
        if not self.handle:
            raise OSError(c.get_last_error(),'Cannot read game process')
        self.config = int(self.baseline['config'],16)
        self.base = int(self.baseline['module_base'],16)
        self.source = self.read_live()
        self.original = self.source
        (self.run/'BASELINE.native.bin').write_bytes(self.original)
        if hashlib.sha256(Path(identity['image']).read_bytes()).hexdigest() != identity['expected_sha256']:
            raise RuntimeError('Loader image changed')
        # Verify PID still names this loader rather than trusting an old PID alone.
        handle = kernel.OpenProcess(0x1000,False,identity['pid'])
        if not handle:
            raise RuntimeError('Loader is no longer available')
        try:
            image = c.create_unicode_buffer(32768); count = w.DWORD(len(image))
            if not kernel.QueryFullProcessImageNameW(handle,0,image,c.byref(count)) or Path(image.value).resolve()!=Path(identity['image']).resolve():
                raise RuntimeError('Loader PID identity changed')
        finally:
            kernel.CloseHandle(handle)
        import frida
        self.session = frida.get_local_device().attach(identity['pid'])
        settings = {'destination':self.baseline['config'],'game_pid':self.baseline['pid'],'size':1752}
        javascript = (PANEL/'writer.js').read_text().replace('__SETTINGS__',json.dumps(settings))
        self.agent = self.session.create_script(javascript)
        self.agent.on('message',self.on_message)
        self.session.on('detached',self.on_detached)
        self.agent.load()
        self.error = None
        self.ready = True
        self.last_write = None
        validate_pairs(self.overrides, self.source)
        self.agent.exports_sync.configure(self.patches(),self.enabled,self.revision)
        atomic_json(self.run/'identity.json', {'game':self.baseline,'loader':identity})

    def reconnect_loop(self):
        while not self.stop_event.is_set():
            if not self.ready or self.error:
                with self.mutation_lock:
                    try:
                        self.detach()
                        self.connect()
                    except Exception as error:
                        self.ready = False
                        self.error = str(error)
                        self.detach()
            self.stop_event.wait(3)

    def detach(self):
        agent, session, handle = self.agent, self.session, self.handle
        self.agent = self.session = self.handle = None
        self.ready = False
        for operation in [lambda: agent.exports_sync.cleanup() if agent else None,
                          lambda: agent.unload() if agent else None,
                          lambda: session.detach() if session else None]:
            try: operation()
            except Exception: pass
        if handle: self.kernel.CloseHandle(handle)

    def on_detached(self, reason, crash=None):
        self.error = 'Loader connection ended: '+str(reason)
        self.ready = False

    def on_message(self,message,data):
        with self.lock:
            payload = message.get('payload',{})
            if message['type']=='error' or payload.get('kind')=='error':
                self.error = message.get('stack') or payload.get('message','Hook error')
                return
            if payload.get('kind')=='write':
                self.source = bytes.fromhex(payload['source_hex'])
                self.last_write = payload
                self.count += 1
                self.events.append(payload)

    def read_live(self):
        if self.demo:
            blob = bytearray(self.source)
            if self.enabled:
                for patch in self.patches():blob[patch['offset']:patch['offset']+len(patch['bytes'])]=bytes(patch['bytes'])
            return bytes(blob)
        root = struct.unpack('<Q',self.read(self.handle,self.base+0x465688,8))[0]
        target = struct.unpack('<Q',self.read(self.handle,root,8))[0]
        if hex(root)!=self.baseline['root'] or target!=self.config:
            raise RuntimeError('Configuration identity changed; reconnect after a fresh capture')
        return self.read(self.handle,self.config,1752)

    def patches(self):
        return [{'offset':FIELDS[k]['offset'],'bytes':list(struct.pack(FORMATS[FIELDS[k]['type']],v if FIELDS[k]['type']=='f32' else int(v)))} for k,v in self.wire_values(self.overrides).items()]

    def snapshot(self):
        with self.mutation_lock, self.lock:
            try:
                live = self.read_live() if self.ready else self.source
            except Exception as error:
                self.error = str(error)
                self.ready = False
                live = self.source
            objects = {}
            if not self.demo and self.ready:
                for module in CATALOG['modules']:
                    obj = struct.unpack('<Q',self.read(self.handle,self.base+int(module['object_slot_rva'],16),8))[0]
                    if struct.unpack('<Q',self.read(self.handle,obj,8))[0]!=self.base+int(module['vtable_rva'],16):
                        raise RuntimeError('Module identity changed: '+module['name'])
                    objects[module['id']] = {'enabled':bool(self.read(self.handle,obj+0x84,1)[0]),'key':struct.unpack('<I',self.read(self.handle,obj+0x80,4))[0]}
                    if module['id'] in ('auto-clicker','lag-range','backtrack','right-clicker'):
                        objects[module['id']]['display']=self.read(self.handle,obj+0x20,64).split(b'\0',1)[0].decode('ascii','replace')
            last = self.last_write or {}
            age = time.time()-last.get('time',0)/1000 if last else None
            actual = decode(live)
            matches = all(actual[k] == v for k,v in self.wire_values(self.overrides).items()) if self.enabled else True
            object_matches = all((objects.get(m['id'],{}).get('key') == 0 and objects.get(m['id'],{}).get('enabled') == bool(self.overrides[m['id']+'.enabled'])) for m in CATALOG['modules'] if m['id'] in self.managed_bindings()) if self.ready and not self.demo and self.enabled else True
            confirmed = self.demo or (self.ready and not self.error and age is not None and age < 8 and last.get('revision')==self.revision and last.get('result')==1 and matches and object_matches)
            return {'product':'driplite-studio','catalog':CATALOG,'token':self.token,'demo':self.demo,'connected':self.ready and not bool(self.error),'error':self.error,'persistence_error':self.persistence_error,'profiles':self.store.list(),'enabled':self.enabled,'revision':self.revision,'confirmed':confirmed,'values':actual,'source_values':decode(self.source),'overrides':self.overrides.copy(),'objects':objects,'write_count':self.count,'last_write_age':age,'last_write_revision':last.get('revision'),'last_write_result':last.get('result'),'undo_available':bool(self.history),'session':{'game_pid':self.baseline['pid'],'run':str(self.run)}}

    def change(self,action,body):
        # Never hold the event callback lock across synchronous Frida RPC.
        with self.mutation_lock:
            if body.get('revision') != self.revision:
                raise ValueError('Settings changed in another window; refresh and retry')
            if self.closed:raise RuntimeError('Service is stopping')
            if action=='profile-save':
                self.store.save(body.get('name'),self.overrides,self.enabled)
                return self.snapshot()
            if action=='profile-delete':
                self.store.delete(body.get('name'))
                return self.snapshot()
            new = self.overrides.copy(); enabled = self.enabled
            if action=='patch':new.update(validate_values(body.get('values')))
            elif action=='import':
                new = validate_values(body.get('values'))
                if 'enabled' in body:
                    if not isinstance(body['enabled'],bool):raise ValueError('Boolean required')
                    enabled=body['enabled']
            elif action=='profile-load':new, enabled = self.store.load(body.get('name'))
            elif action=='reset':
                module = body.get('module')
                if module is not None and module not in {m['id'] for m in CATALOG['modules']}:raise ValueError('Unknown module')
                new = {k:v for k,v in new.items() if not (module is None or k.startswith(module+'.'))}
            elif action=='active':
                if not isinstance(body.get('enabled'),bool):raise ValueError('Boolean required')
                enabled = body['enabled']
            elif action=='undo':
                if not self.history:raise ValueError('Nothing to undo')
                new, enabled = self.history[-1]
            else:raise ValueError('Unknown action')
            # Pin state only for modules whose key was explicitly rebound. This
            # prevents the loader's old-key state from undoing managed toggles.
            live=decode(self.read_live()) if self.ready else decode(self.source)
            for m in CATALOG['modules']:
                key,state=m['id']+'.key',m['id']+'.enabled'
                if key in new and state in FIELDS and state not in new:
                    new[state]=int(live[state])
            validate_pairs(new,self.source)
            previous = (self.overrides.copy(),self.enabled)
            patches=[{'offset':FIELDS[k]['offset'],'bytes':list(struct.pack(FORMATS[FIELDS[k]['type']],v if FIELDS[k]['type']=='f32' else int(v)))} for k,v in self.wire_values(new).items()]
            if self.agent and self.ready:self.agent.exports_sync.configure(patches,enabled,self.revision+1)
            with self.lock:
                self.overrides,self.enabled = new,enabled
                if action=='undo':self.history.pop()
                else:self.history.append(previous)
                self.revision += 1
            (self.run/'latest_settings.json').write_text(json.dumps({'format':'driplite-overrides-v1','values':new,'enabled':enabled,'revision':self.revision},indent=2))
            try:
                atomic_json(self.data/'autosave.json',{'format':'driplite-overrides-v1','values':new,'enabled':enabled})
                self.persistence_error=None
            except OSError as error:
                self.persistence_error='Settings applied but automatic save failed: '+str(error)
            return self.snapshot()

    def close(self):
        if self.closed:return
        self.closed=True
        self.stop_event.set()
        if self.worker:self.worker.join(timeout=10)
        if self.hotkey_worker:self.hotkey_worker.join(timeout=2)
        with self.mutation_lock:
            self.detach()
        atomic_json(self.run/'events.json',{'writes':list(self.events),'count':self.count,'final_overrides':self.overrides})


def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=8770);parser.add_argument('--demo',action='store_true');parser.add_argument('--data',type=Path);parser.add_argument('--open-browser',action='store_true');parser.add_argument('--preset',choices=['nice','123'],default='nice');args=parser.parse_args(argv)
    control=Controller(args.demo,args.data)
    origin='http://127.0.0.1:'+str(args.port)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def send(self,status,data,content_type='application/json; charset=utf-8'):
            body=json.dumps(data,ensure_ascii=False,allow_nan=False).encode() if not isinstance(data,bytes) else data
            self.send_response(status);self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");self.end_headers();self.wfile.write(body)
        def valid_host(self):return self.headers.get('Host')=='127.0.0.1:'+str(args.port)
        def do_GET(self):
            if not self.valid_host():return self.send(403,{'error':'Invalid host'})
            path=urlparse(self.path).path
            try:
                if path=='/api/state':return self.send(200,{**control.snapshot(),'preset':args.preset})
                files={'/':(PANEL/'index.html','text/html; charset=utf-8'),'/app.js':(PANEL/'app.js','text/javascript; charset=utf-8'),'/style.css':(PANEL/'style.css','text/css; charset=utf-8')}
                if path in files:
                    file,kind=files[path];return self.send(200,file.read_bytes(),kind)
                return self.send(404,{'error':'Not found'})
            except Exception as error:return self.send(503,{'error':str(error)})
        def do_POST(self):
            if not self.valid_host() or self.headers.get('Origin',origin)!=origin or self.headers.get('X-Panel-Token')!=control.token:return self.send(403,{'error':'Invalid session'})
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<65536:raise ValueError('Invalid body size')
                if self.headers.get('Content-Type')!='application/json':raise ValueError('JSON required')
                body=json.loads(self.rfile.read(length));action=urlparse(self.path).path.removeprefix('/api/')
                if not isinstance(body,dict):raise ValueError('JSON object required')
                if action=='stop':
                    if body.get('revision')!=control.revision:raise ValueError('Settings changed; refresh and retry')
                    control.close();self.send(200,{'stopped':True});threading.Thread(target=server.shutdown,daemon=True).start();return
                return self.send(200,control.change(action,body))
            except (ValueError,KeyError,TypeError) as error:return self.send(400,{'error':str(error)})
            except Exception as error:return self.send(503,{'error':str(error)})
    try:server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    except Exception:
        control.close()
        raise
    atomic_json(control.data/'server.json',{'url':origin,'demo':args.demo,'run':str(control.run),'pid':os.getpid()})
    print(json.dumps({'url':origin,'mode':'demo' if args.demo else 'live','run':str(control.run)}),flush=True)
    if args.open_browser:
        import webbrowser
        webbrowser.open(origin)
    try:server.serve_forever()
    finally:control.close();server.server_close()


if __name__=='__main__':main()
