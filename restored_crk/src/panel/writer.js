'use strict';
const settings = __SETTINGS__;
const destination = ptr(settings.destination);
const image = Process.getModuleByName('Drip.exe');
const getPid = new NativeFunction(Process.getModuleByName('kernel32.dll').getExportByName('GetProcessId'), 'uint', ['pointer']);
let patches = [], enabled = true, revision = 0;
const hex = b => Array.from(new Uint8Array(b), n => n.toString(16).padStart(2, '0')).join('');
const hook = Interceptor.attach(Process.getModuleByName('kernelbase.dll').getExportByName('WriteProcessMemory'), {
  onEnter(args) {
    this.event = null; this.buffer = null;
    try {
      if (!args[1].equals(destination) || Number(args[3].toString()) !== settings.size || getPid(args[0]) !== settings.game_pid) return;
      if (this.returnAddress.sub(image.base).toString() !== '0x28103') return;
      const source = args[2].readByteArray(settings.size);
      this.event = {kind:'write', revision, enabled, tid:Process.getCurrentThreadId(), time:Date.now(), source_hex:hex(source), changed_offsets:[]};
      if (enabled && patches.length) {
        const buffer = Memory.alloc(settings.size);
        buffer.writeByteArray(source);
        for (const patch of patches) buffer.add(patch.offset).writeByteArray(patch.bytes);
        const next = buffer.readByteArray(settings.size), a = new Uint8Array(source), b = new Uint8Array(next);
        for (let i=0;i<a.length;i++) if (a[i] !== b[i]) this.event.changed_offsets.push(i);
        this.event.outgoing_hex = hex(next);
        this.buffer = buffer; args[2] = buffer;
      } else this.event.outgoing_hex = this.event.source_hex;
    } catch (error) { send({kind:'error', message:String(error)}); }
  },
  onLeave(retval) {
    if (this.event) { this.event.result = retval.toInt32(); send(this.event); }
    this.buffer = null;
  }
});
rpc.exports = {
  configure(next, active, version) {
    for (const p of next) {
      if (!Number.isInteger(p.offset) || p.offset < 0 || !p.bytes.length || p.offset+p.bytes.length > settings.size || p.bytes.some(b => !Number.isInteger(b) || b<0 || b>255)) throw new Error('Invalid patch');
    }
    patches = next; enabled = active; revision = version; return revision;
  },
  cleanup() { patches=[]; enabled=false; hook.detach(); return true; }
};
