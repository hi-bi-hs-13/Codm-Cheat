#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase B: Safe unpacking of VMProtect 3.x stub via Unicorn CPU emulation.
NO real execution of the sample — pure userspace emulation with:
  - faithful PE image mapping at preferred base 0x140000000
  - IAT pre-filled with fake API stubs (ret) dispatched from Python
  - TEB/PEB/stack/GS emulation, CPUID/RDTSC/SYSCALL handling
  - OEP detection via block-hook on .text
  - section dumps + console output capture
"""
import struct, os, sys, time, traceback
import pefile
from unicorn import *
from unicorn.x86_const import *
import synthdlls

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, '..', '02_samples', 'test.bin')
OUT = os.path.join(HERE, 'out')
os.makedirs(OUT, exist_ok=True)

data = open(SAMPLE, 'rb').read()
pe = pefile.PE(SAMPLE)
oh = pe.OPTIONAL_HEADER
BASE = oh.ImageBase
SOI = oh.SizeOfImage
SOH = oh.SizeOfHeaders
EP = BASE + oh.AddressOfEntryPoint

SECS = []
for s in pe.sections:
    nm = s.Name.rstrip(b'\x00').decode('utf-8', 'replace')
    SECS.append((nm, s.VirtualAddress, s.Misc_VirtualSize, s.SizeOfRawData, s.PointerToRawData, s.Characteristics))

def rva2off(rva):
    for (nm, va, vs, rs, rp, ch) in SECS:
        if va <= rva < va + max(vs, rs) and rs:
            d = rva - va
            if d < rs: return rp + d
    return None

def fileoff_to_rva(off):
    # reverse of rva2off: raw file offset -> RVA (for SEC_IMAGE views)
    if off < SOH:
        return off  # headers map 1:1 at RVA 0
    for (nm, va, vs, rs, rp, ch) in SECS:
        if rs and rp <= off < rp + rs:
            return va + (off - rp)
    return None

# memory layout constants
STACK_BASE = 0x7FF000000000
STACK_SIZE = 0x400000
KUSD_BASE  = 0x7FFE0000          # KUSER_SHARED_DATA — FIXED address on real Windows!
TEB_BASE   = 0x7FF600000000       # TEB relocated (0x7FFE0000 belongs to KUSD)
PEB_BASE   = 0x7FFDF000
HEAP_BASE  = 0x300000000
HEAP_SIZE  = 0x8000000
API_BASE   = 0x100000000
API_SIZE   = 0x2100000          # 33MB: synth DLLs + stubs
SYNTH_SLOT_START = API_BASE + 0x100000   # synth DLL images at +1MB
SYNTH_SLOT_SIZE  = 0x100000              # 1MB per DLL
STUB_START = API_BASE + 0x2000000         # API stubs at +32MB
VIRT_BASE  = 0x500000000
MAGIC_RET  = 0x0009ABCD00000000  # unmapped sentinel

mu = Uc(UC_ARCH_X86, UC_MODE_64)
os.makedirs(OUT, exist_ok=True)
LOG = open(os.path.join(HERE, 'emu_log_v2.txt'), 'a')

def log(msg):
    line = str(msg)
    print(line, flush=True)
    LOG.write(line + '\n'); LOG.flush()

# ---------------- memory setup ----------------
def pg(x): return x & ~0xFFF
def pgup(x): return (x + 0xFFF) & ~0xFFF

mu.mem_map(BASE, pgup(SOI) + 0x1000, UC_PROT_ALL)
mu.mem_write(BASE, data[:0x400])  # headers
for (nm, va, vs, rs, rp, ch) in SECS:
    if rs:
        mu.mem_write(BASE + va, data[rp:rp+rs])

# apply faithful per-section protections
async def _unused(): pass
def apply_prot():
    prot_map = []
    for (nm, va, vs, rs, rp, ch) in SECS:
        e = bool(ch & 0x20000000); r = bool(ch & 0x40000000); w = bool(ch & 0x80000000)
        p = (UC_PROT_EXEC if e else 0) | (UC_PROT_READ if r else 0) | (UC_PROT_WRITE if w else 0)
        prot_map.append((nm, va, vs, p))
    for (nm, va, vs, p) in prot_map:
        if vs == 0: continue
        try: mu.mem_protect(BASE + pg(va), pgup(vs), p)
        except Exception as e: log(f"prot {nm}: {e}")

mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(TEB_BASE, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(KUSD_BASE, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(PEB_BASE, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
LDR_HEAD    = 0x7FFD0000
LDR_ENTRIES = 0x7FFD1000
LDR_NAMES   = 0x7FFD4000
mu.mem_map(LDR_HEAD, 0x8000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
mu.mem_map(API_BASE, API_SIZE, UC_PROT_ALL)

# KUSER_SHARED_DATA (0x7FFE0000) — critical for VMP anti-debug:
# KdDebuggerEnabled @ +0x2D6 MUST be 0
# ---- SESSION4 FIX: unified virtual clock ----
# Real Windows invariant: KSYSTEM_TIME {LowPart, High1Time, High2Time} always has High1==High2.
# Old bug: High1=0x01D80000, High2=0x01D8 -> VMP environment sanity check fails -> verdict abort.
# All time sources (KUSD/FILETIME APIs/QPC/GetTickCount) now derive from ONE advancing clock.
FT_2026_09_20 = 0x01E0A28E12C04000   # fixed base FILETIME (Sept 2026-ish, 100ns units)
_vt_ms = [0x00200000]                 # virtual uptime in ms (~35 min), advanced by next_tick()
def virt_filetime():
    return FT_2026_09_20 + _vt_ms[0] * 10000   # ms -> 100ns
kusd = bytearray(0x1000)
struct.pack_into('<II', kusd, 0x000, 0x0ABCDEF0, 0x0FA00000)      # TickCountLow, Multiplier
_it = FT_2026_09_20 - 0x0A1B2C3D0000   # InterruptTime slightly behind SystemTime, still consistent
struct.pack_into('<III', kusd, 0x008, _it & 0xFFFFFFFF, (_it >> 32) & 0xFFFFFFFF, (_it >> 32) & 0xFFFFFFFF)  # InterruptTime High1==High2 ★
_ft = virt_filetime()
struct.pack_into('<III', kusd, 0x014, _ft & 0xFFFFFFFF, (_ft >> 32) & 0xFFFFFFFF, (_ft >> 32) & 0xFFFFFFFF)  # SystemTime High1==High2 ★ FIX
struct.pack_into('<III', kusd, 0x020, 0, 0, 0)                      # TimeZoneBias (consistent zero)
struct.pack_into('<III', kusd, 0x320, _vt_ms[0] * 10000 & 0xFFFFFFFF, (_vt_ms[0] * 10000) >> 32 & 0xFFFFFFFF, (_vt_ms[0] * 10000) >> 32 & 0xFFFFFFFF)  # TickCount High1==High2 ★
struct.pack_into('<I', kusd, 0x26C, 10)                              # NtMajorVersion
struct.pack_into('<I', kusd, 0x270, 0)                               # NtMinorVersion
struct.pack_into('<H', kusd, 0x278, 0x1CD)                          # ProductType (WinNT)
kusd[0x2D6] = 0                                                     # KdDebuggerEnabled = FALSE ★
kusd[0x2FE] = 0                                                     # KdDebuggerEnabled (x64 offset) = FALSE ★
kusd[0x2FF] = 1                                                     # KdDebuggerNotPresent = TRUE ★
struct.pack_into('<I', kusd, 0x330, 0xA1B2C3D4)                    # Cookie
kusd[0x3C4:0x3C4+18] = "C:\\WINDOWS".encode('utf-16le') + b'\x00\x00'  # NtSystemRoot
for _cs in range(0, 0x1000, 0x100):   # unicorn 2.1.4 quirk: full-page write at region end fails — chunk it
    mu.mem_write(KUSD_BASE + _cs, bytes(kusd[_cs:_cs+0x100]))

# TEB
STACK_TOP = STACK_BASE + STACK_SIZE - 0x10000
teb = bytearray(0x1000)
struct.pack_into('<Q', teb, 0x08, STACK_TOP)          # StackBase
struct.pack_into('<Q', teb, 0x10, STACK_BASE)          # StackLimit
struct.pack_into('<Q', teb, 0x30, TEB_BASE)            # Self
struct.pack_into('<Q', teb, 0x60, PEB_BASE)           # ProcessEnvironmentBlock
mu.mem_write(TEB_BASE, bytes(teb))

# PEB
peb = bytearray(0x1000)
peb[0x02] = 0                                          # BeingDebugged
struct.pack_into('<Q', peb, 0x08, BASE)               # ImageBaseAddress
struct.pack_into('<Q', peb, 0x28, HEAP_BASE)          # ProcessHeap
# fake Ldr (points to real LDR region built later)
struct.pack_into('<Q', peb, 0x10, LDR_HEAD)   # Ldr
mu.mem_write(PEB_BASE, bytes(peb))
# ProcessParameters (minimal: CommandLine at +0x70)
pp = bytearray(0x200)
cmdline = "C:\\CODM\\loader.exe"
struct.pack_into('<Q', pp, 0x70 + 8, PEB_BASE + 0x600)  # CommandLine.Buffer
struct.pack_into('<H', pp, 0x70, len(cmdline)*2)
struct.pack_into('<H', pp, 0x72, len(cmdline)*2)
mu.mem_write(PEB_BASE + 0x500, bytes(pp))
mu.mem_write(PEB_BASE + 0x600, cmdline.encode('utf-16le'))
struct.pack_into('<Q', peb, 0x18, PEB_BASE + 0x500)
mu.mem_write(PEB_BASE, bytes(peb))

mu.msr_write(0xC0000101, TEB_BASE)  # IA32_GS_BASE

# zero debug registers (unicorn default DR2/DR5=0x400 trips hardware-BP checks!)
for _dr in (UC_X86_REG_DR0, UC_X86_REG_DR1, UC_X86_REG_DR2, UC_X86_REG_DR3, UC_X86_REG_DR5):
    try: mu.reg_write(_dr, 0)
    except Exception: pass

# ---------------- API stubs ----------------
api_next = STUB_START
api_by_addr = {}
api_calls = {}
synth_built = {}   # dllname_lower -> synth base
synth_meta = []
modules_by_name = {}

STUB_CODE = bytes.fromhex(
    '4c8bdc'              # mov r11, rsp
    '49894b08'            # mov [r11+8], rcx      (shadow: arg1)
    '49895310'            # mov [r11+0x10], rdx   (arg2)
    '49894820'            # mov [r11+0x20], r8    — wait wrong modrm; built below
)
# build proper prologue programmatically:
def _build_stub():
    code = bytes.fromhex('4c8bdc')                 # mov r11, rsp
    code += bytes.fromhex('49894b08')               # mov [r11+08], rcx
    code += bytes.fromhex('49895310')               # mov [r11+10], rdx
    code += bytes.fromhex('49894b18')               # mov [r11+18], r8  (r8 stored via rcx? no — this encodes rcx again; fix below)
    # NOTE: encoding mov [r11+X], r8/r9 requires different modrm bytes — use emit helper:
    return code

def emit_mov_mem_r64(base_rmi, disp, src_rmi):
    # mov [r11+disp8], r64: REX.W+B (src ext) + 89 /r with mod=01 rm=011(r11 needs REX.B)
    rex = 0x49 if src_rmi >= 8 or True else 0x48
    # r11 is reg-ext base (rm=011 + REX.B=1); src register R/S fields
    if src_rmi < 8:
        rex = 0x49
        modrm = 0x40 | (src_rmi << 3) | 0x03
    else:
        rex = 0x4D
        modrm = 0x40 | ((src_rmi - 8) << 3) | 0x03
    return bytes([rex, 0x89, modrm, disp])

def build_realistic_stub():
    b = bytes.fromhex('4c8bdc')                      # mov r11, rsp
    b += emit_mov_mem_r64(11, 0x08, 1)               # [r11+08] = rcx
    b += emit_mov_mem_r64(11, 0x10, 2)               # [r11+10] = rdx
    b += emit_mov_mem_r64(11, 0x18, 8)               # [r11+18] = r8
    b += emit_mov_mem_r64(11, 0x20, 9)               # [r11+20] = r9
    b += bytes.fromhex('55')                         # push rbp
    b += bytes.fromhex('57')                         # push rdi
    b += bytes.fromhex('4881ec80000000')             # sub rsp, 0x80
    b += bytes.fromhex('488d6c2420')                 # lea rbp, [rsp+0x20]
    b += bytes.fromhex('4881c480000000')             # add rsp, 0x80 (imm32 — imm8 0x80 would be negative!)
    b += bytes.fromhex('5f')                         # pop rdi
    b += bytes.fromhex('5d')                         # pop rbp
    b += bytes.fromhex('c3')                         # ret
    return b

REAL_STUB = build_realistic_stub()
STUB_SPACING = 0x40
STUB_AREA_OFF = 0x10000          # stubs live INSIDE the synth DLL's image (anti anti-hook!)
_slot_stubs = {}                # dll_key -> next stub offset within slot

def new_api(dll, name):
    key = dll.lower().replace('\\', '/').split('/')[-1] or 'unknown.dll'
    if key in synth_built:
        slot = synth_built[key]
        off = _slot_stubs.get(key, STUB_AREA_OFF)
        if off + STUB_SPACING >= SYNTH_SLOT_SIZE:   # overflow → fall back to global area
            slot = STUB_START
            off = _slot_stubs.get('__global__', 0)
            _slot_stubs['__global__'] = off + STUB_SPACING
        else:
            _slot_stubs[key] = off + STUB_SPACING
    else:
        slot = STUB_START
        off = _slot_stubs.get('__global__', 0)
        _slot_stubs['__global__'] = off + STUB_SPACING
    addr = slot + off
    mu.mem_write(addr, REAL_STUB)
    api_by_addr[addr] = (dll, str(name))
    return addr

def handle_to_dll(h):
    if h == BASE: return 'exe'
    for k, b in synth_built.items():
        if b == h: return k
    return f'mod_{hex(h)}'

def make_eat_hook(dll, names, arr_base):
    def hook(uc, access, address, size, value, ud):
        idx = (address - arr_base) // 4
        if 0 <= idx < len(names):
            log(f"    EAT resolve: {dll}!{names[idx]}")
    return hook

def ensure_synth(dllname):
    key = dllname.lower().replace('\\', '/').split('/')[-1]
    if not key: key = 'unknown.dll'
    if key in synth_built: return synth_built[key]
    if key.startswith('api-ms-win-crt'):
        exports = synthdlls.UCRT
    else:
        exports = synthdlls.EXPORT_LISTS.get(key, synthdlls.GENERIC)
    # merge extra exports discovered iteratively (auto-repair mechanism)
    extras = synthdlls.load_extra_exports()
    if key in extras:
        exports = sorted(set(exports) | set(extras[key]))
        log(f"synth {key}: +{len(extras[key])} extra exports from extras file")
    slot = SYNTH_SLOT_START + len(synth_built) * SYNTH_SLOT_SIZE
    if key in ('ws2_32.dll', 'wsock32.dll'):
        ords = synthdlls.WS2_32_ORDINALS
    elif key == 'wldap32.dll':
        ords = synthdlls.WLDAP32_ORDINALS
    else:
        ords = None
    img, meta = synthdlls.build_synth_dll(key, exports, slot, new_api, explicit_ordinals=ords)
    mu.mem_write(slot, img)
    synth_built[key] = slot
    synth_meta.append(meta)
    arr = meta['func_arr_off']
    mu.hook_add(UC_HOOK_MEM_READ, make_eat_hook(key, meta['names'], arr),
                begin=arr, end=arr + 4*len(meta['names']))
    log(f"synth DLL built: {key} @ {hex(slot)} ({len(meta['names'])} exports)")
    return slot

def read_cstr(addr, maxlen=520):
    out = b''
    while len(out) < maxlen:
        chunk = mu.mem_read(addr + len(out), 64)
        if b'\x00' in chunk:
            out += chunk[:chunk.index(b'\x00')]
            break
        out += chunk
    try: return out.decode('utf-8', 'replace')
    except: return out.decode('latin1', 'replace')

def read_wstr(addr, maxlen=520):
    out = b''
    while len(out) < maxlen*2:
        chunk = mu.mem_read(addr + len(out), 128)
        if b'\x00\x00' in chunk:
            idx = chunk.index(b'\x00\x00')
            # ensure even alignment
            if (idx % 2) == 0:
                out += chunk[:idx]; break
        out += chunk
    return out.decode('utf-16le', 'replace')

def get_module_handle(name):
    if not name:
        return BASE
    return ensure_synth(name)

def virt_alloc(size, addr=0):
    global VIRT_PTR
    if addr == 0:
        addr = VIRT_PTR
        VIRT_PTR = pgup(addr + max(size, 0x1000))
    a0, a1 = pg(addr), pgup(addr + max(size, 1))
    try: mu.mem_map(a0, a1 - a0, UC_PROT_ALL)
    except UcError: pass
    return addr

VIRT_PTR = VIRT_BASE

WINPROT = {0x01: UC_PROT_NONE, 0x02: UC_PROT_READ, 0x04: UC_PROT_READ|UC_PROT_WRITE,
           0x08: UC_PROT_READ|UC_PROT_WRITE, 0x10: UC_PROT_EXEC,
           0x20: UC_PROT_EXEC|UC_PROT_READ, 0x40: UC_PROT_ALL, 0x80: UC_PROT_ALL}

def do_protect(addr, size, prot):
    a0, a1 = pg(addr), pgup(addr + max(size, 1))
    p = WINPROT.get(prot & 0xFF, UC_PROT_ALL)
    try: mu.mem_protect(a0, a1 - a0, p)
    except Exception as e: log(f"    mem_protect({hex(a0)},{hex(a1-a0)}) -> {e}")

tick = 0x15000000000
def next_tick():
    global tick
    tick += 20000
    _vt_ms[0] += 15   # advance virtual uptime ~15ms per call (plausible 15.6ms tick)
    return tick

CONSOLE_HANDLE_OUT = 0x11
CONSOLE_HANDLE_ERR = 0x12
file_handles = {}
next_fh = 0x100
next_file_handle = 0
next_section_handle = 0
mapped_views = []
cert_store_counter = 0
socket_counter = 0

def handle_ntqueryinfo(uc, cls, buf):
    """NtQueryInformationProcess with anti-debug-correct semantics.
    Returns the NTSTATUS to hand back to the caller."""
    log(f"    NtQIP(cls={hex(cls)}, buf={hex(buf)})")
    if buf == 0:
        return 0
    if cls == 0x1F:      # ProcessDebugFlags (INVERTED: 1 = not debugged)
        uc.mem_write(buf, struct.pack('<I', 1))
        return 0
    if cls == 0x07:       # ProcessDebugPort
        uc.mem_write(buf, struct.pack('<Q', 0))
        return 0
    if cls == 0x1E:       # ProcessDebugObjectHandle: SUCCESS means debugger!
        uc.mem_write(buf, struct.pack('<Q', 0))
        return 0xC0000353  # STATUS_PORT_NOT_SET (no debug object)
    if cls == 0x1B:       # ProcessAffinityMask
        uc.mem_write(buf, struct.pack('<Q', 0xFF))
        return 0
    if cls == 0x05:       # ProcessCookie
        uc.mem_write(buf, struct.pack('<Q', 0x12345678))
        return 0
    uc.mem_write(buf, b'\x00' * 0x40)
    return 0

_winsta_buf = 0
def _on_winsta_read(uc, access, address, size, value, ud):
    rip = uc.reg_read(UC_X86_REG_RIP)
    log(f"    WINSTA BUF READ @ {hex(address)} size={size} from RIP={hex(rip)}")

def dispatch(uc, dll, name):
    global VIRT_PTR, mapped_views, HEAP_PTR, next_fh, next_file_handle, next_section_handle, cert_store_counter, socket_counter, _winsta_buf
    key = name.lower()
    api_calls[key] = api_calls.get(key, 0) + 1
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8  = uc.reg_read(UC_X86_REG_R8)
    r9  = uc.reg_read(UC_X86_REG_R9)
    rsp = uc.reg_read(UC_X86_REG_RSP)
    ret = 0

    if key in ('loadlibrarya', 'loadlibraryw', 'loadlibraryexa', 'loadlibraryexw'):
        try:
            nm = read_cstr(rcx) if 'a' in key[-2:].lower() or key.endswith('exa') else read_wstr(rcx)
        except Exception:
            nm = '?'
        h = get_module_handle(nm)
        log(f"API {key}('{nm}') -> {hex(h)}")
        ret = h
    elif key in ('getmodulehandlea', 'getmodulehandlew', 'getmodulehandleexa', 'getmodulehandleexw'):
        nm = ''
        if rcx:
            try: nm = read_cstr(rcx) if key.endswith('a') else read_wstr(rcx)
            except Exception: nm = '?'
        if not nm: ret = BASE
        else: ret = get_module_handle(nm)
        log(f"API {key}('{nm}') -> {hex(ret)}")
    elif key == 'getprocaddress':
        h = rcx
        d = handle_to_dll(h)
        if rdx > 0x10000:
            try: fn = read_cstr(rdx)
            except Exception: fn = f'ptr_{hex(rdx)}'
        else:
            fn = f'ord#{rdx & 0xFFFF}'
        ret = new_api(d, fn)
        if api_calls.get(key, 0) < 400:
            log(f"API GetProcAddress({d}, '{fn}') -> {hex(ret)}")
    elif key in ('virtualalloc', 'virtualallocex'):
        if key == 'virtualalloc':
            ret = virt_alloc(rdx, rcx)
        else:
            ret = VIRT_PTR  # remote alloc — record target size
            log(f"API VirtualAllocEx(remote, size={hex(rdx)}) @ {hex(ret)}")
            globals()['VIRT_PTR'] = pgup(ret + max(rdx, 0x1000))
        log(f"API VirtualAlloc(0x{rcx:x}, size=0x{rdx:x}) -> {hex(ret)}")
    elif key in ('virtualprotect', 'virtualprotectex'):
        if key == 'virtualprotect':
            do_protect(rcx, rdx, r9 & 0xFF)
            if r8: uc.mem_write(r8, struct.pack('<I', 0x40))
        ret = 1
    elif key == 'virtualfree':
        ret = 1
    elif key == 'localalloc':
        global HEAP_PTR  # noqa (already declared at function top)
        HEAP_PTR = (HEAP_PTR + rdx + 0x1F) & ~0xF
        ret = HEAP_PTR
    elif key == 'localfree':
        ret = 0
    elif key == 'getmodulefilenamew':
        s = "C:\\CODM\\loader.exe"
        b = s.encode('utf-16le')
        uc.mem_write(rdx, b + b'\x00\x00')
        ret = len(s)
    elif key == 'getmodulefilenamea':
        s = "C:\\CODM\\loader.exe"
        uc.mem_write(rdx, s.encode() + b'\x00')
        ret = len(s)
    elif key == 'sleep':
        pass
    elif key == 'getsystemtimeasfiletime':
        uc.mem_write(rcx, struct.pack('<Q', virt_filetime()))   # SESSION4: advancing, consistent with KUSD
    elif key == 'getsystemtime':
        ft = virt_filetime()
        import datetime as _dt
        ts = (ft - 116444736000000000) / 1e7
        d = _dt.datetime(1601, 1, 1) + _dt.timedelta(seconds=ts)
        st = struct.pack('<8H', d.year, d.month, d.weekday(), d.day, d.hour, d.minute, d.second, d.microsecond // 1000)
        if rcx: uc.mem_write(rcx, st)
        ret = 1
    elif key == 'getlocaltime':
        ft = virt_filetime()
        import datetime as _dt
        ts = (ft - 116444736000000000) / 1e7
        d = _dt.datetime(1601, 1, 1) + _dt.timedelta(seconds=ts)
        st = struct.pack('<8H', d.year, d.month, d.weekday(), d.day, d.hour, d.minute, d.second, d.microsecond // 1000)
        if rcx: uc.mem_write(rcx, st)
        ret = 1
    elif key == 'systemtimetofiletime':
        if r8 and rdx:
            st = struct.unpack('<8H', uc.mem_read(rdx, 16))
            import datetime as _dt
            try:
                d = _dt.datetime(st[0], st[1], st[3], st[4], st[5], st[6], st[7] * 1000)
                ft = int((d - _dt.datetime(1601, 1, 1)).total_seconds() * 1e7) + 116444736000000000
                uc.mem_write(r8, struct.pack('<Q', ft))
            except Exception:
                uc.mem_write(r8, struct.pack('<Q', virt_filetime()))
        ret = 1
    elif key == 'filetimetosystemtime':
        if rdx and r8:
            ft = struct.unpack_from('<Q', uc.mem_read(rdx, 8), 0)[0]
            import datetime as _dt
            d = _dt.datetime(1601, 1, 1) + _dt.timedelta(seconds=(ft - 116444736000000000) / 1e7)
            uc.mem_write(r8, struct.pack('<8H', d.year, d.month, d.weekday(), d.day, d.hour, d.minute, d.second, d.microsecond // 1000))
        ret = 1
    elif key == 'getsystemdirectorya' or key == 'getsystemdirectoryw':
        s = 'C:\\Windows\\System32'
        b = s.encode() if key.endswith('a') else s.encode('utf-16le')
        if rdx: uc.mem_write(rdx, b + (b'\x00' if key.endswith('a') else b'\x00\x00'))
        ret = len(s)
    elif key == 'getprocessaffinitymask':
        if rdx: uc.mem_write(rdx, struct.pack('<I', 0xFF))
        if r8:  uc.mem_write(r8,  struct.pack('<I', 0xFF))
        ret = 1
    elif key in ('setprocessaffinitymask',):
        ret = 1
    elif key == 'setthreadaffinitymask':
        ret = 0xFF
    elif key == 'exitprocess':
        log(f"API ExitProcess({rcx}) — IGNORING (continuing emulation to trace post-abort path)")
        return
    elif key == 'freelibrary':
        ret = 1
    elif key == 'getprocesswindowstation':
        ret = 0x1234
    elif key in ('messageboxw', 'messageboxa'):
        # (hWnd=rcx, lpText=rdx, lpCaption=r8, uType=r9)
        try:
            txt = read_wstr(rdx) if key == 'messageboxw' else read_cstr(rdx)
            cap = read_wstr(r8) if key == 'messageboxw' else read_cstr(r8)
            log(f"*** [MESSAGEBOX '{cap}'] {txt} ***")
        except Exception as e:
            log(f"MessageBox parse err: {e}")
        # dump the block trace
        if _block_trace:
            log(f"=== BLOCK TRACE (last {len(_block_trace)} blocks before MessageBox) ===")
            with open(OUT + '/abort_blocktrace.txt', 'w') as f:
                for (a, s) in list(_block_trace)[-200:]:
                    f.write(f"{hex(a)} {s}\n")
                # dump memory around the last 24 blocks for disasm
                for (a, s) in list(_block_trace)[-24:]:
                    try:
                        f.write(f"#MEM {hex(a)} {bytes(mu.mem_read(a - 0x40, s + 0xC0)).hex()}\n")
                    except Exception:
                        pass
            log("block trace + memory dumped to abort_blocktrace.txt")
        ret = 1  # IDOK
    elif key == 'getuserobjectinformationw':
        # (hObj=rcx, nIndex=rdx, pvInfo=r8, nLength=r9, lpnLengthNeeded=st1)
        log(f"    GetUserObjectInformationW(h={hex(rcx)}, idx={rdx}, buf={hex(r8)}, len={r9})")
        if rdx == 2 and r8:      # UOI_NAME = 2 (!!) — write "WinSta0"
            b = "WinSta0".encode('utf-16le') + b'\x00\x00'
            uc.mem_write(r8, b)
            st1 = read_stack_arg(uc, 1)
            if st1: uc.mem_write(st1, struct.pack('<I', len(b)))
            # watchpoint: who reads the station name?
            global _winsta_buf
            _winsta_buf = r8
            try:
                mu.hook_add(UC_HOOK_MEM_READ, _on_winsta_read, begin=r8, end=r8 + 16)
                log(f"    watchpoint set on WinSta0 buffer @ {hex(r8)}")
            except Exception as e:
                log(f"    watchpoint err: {e}")
        elif rdx == 3 and r8:    # UOI_TYPE
            uc.mem_write(r8, "WindowStation".encode('utf-16le') + b'\x00\x00')
            st1 = read_stack_arg(uc, 1)
            if st1: uc.mem_write(st1, struct.pack('<I', 30))
        elif rdx == 1 and r8:    # UOI_FLAGS (USEROBJECTFLAGS: Inherit, Reserved, WSF_VISIBLE)
            uc.mem_write(r8, struct.pack('<III', 0, 0, 1))   # fInherit=0, fReserved=0, WSF_VISIBLE ✓
        ret = 1
    elif key == 'getuserobjectinformationa':
        if rdx == 2 and r8:
            uc.mem_write(r8, b"WinSta0\x00")
        elif rdx == 3 and r8:
            uc.mem_write(r8, b"WindowStation\x00")
        elif rdx == 1 and r8:
            uc.mem_write(r8, struct.pack('<III', 0, 0, 1))
        ret = 1
    elif key in ('charupperbuffw', 'charupperbuffa'):
        # (lpsz=rcx, cchLength=rdx) — uppercase in place, return cchLength
        try:
            if rdx:
                if key == 'charupperbuffw':
                    b = bytearray(uc.mem_read(rcx, rdx * 2))
                    for i in range(0, len(b), 2):
                        c = int.from_bytes(b[i:i+2], 'little')
                        if 0x61 <= c <= 0x7A: b[i:i+2] = bytes([c - 0x20, 0])
                    uc.mem_write(rcx, bytes(b))
                else:
                    b = bytearray(uc.mem_read(rcx, rdx))
                    for i, c in enumerate(b):
                        if 0x61 <= c <= 0x7A: b[i] = c - 0x20
                    uc.mem_write(rcx, bytes(b))
            ret = rdx
        except Exception:
            ret = rdx
    elif key == 'ntopenfile':
        # FileHandle* rcx, DesiredAccess rdx, ObjectAttributes* r8, IoStatusBlock* r9
        try:
            name_ptr = struct.unpack_from('<Q', uc.mem_read(r8 + 0x10, 8), 0)[0]
            us_len = struct.unpack_from('<H', uc.mem_read(name_ptr, 2), 0)[0]
            us_buf = struct.unpack_from('<Q', uc.mem_read(name_ptr + 8, 8), 0)[0]
            path = bytes(uc.mem_read(us_buf, us_len)).decode('utf-16le', 'replace')
            log(f"NtOpenFile('{path}')")
        except Exception as e:
            log(f"NtOpenFile(name parse failed: {e})")
        next_file_handle += 1
        fh = 0x21000 + next_file_handle
        if rcx: uc.mem_write(rcx, struct.pack('<Q', fh))
        ret = 0
    elif key == 'ntcreatesection':
        # rcx=SectionHandle* rdx=DesiredAccess r8=ObjectAttributes* r9=MaxSize* st1=PageProt st2=AllocAttrs st3=FileHandle
        try:
            _prot = read_stack_arg(uc, 1)
            _attrs = read_stack_arg(uc, 2)
            _fh = read_stack_arg(uc, 3)
            log(f"NtCreateSection(desired={hex(rdx)}, pageprot={hex(_prot)}, allocattrs={hex(_attrs)}, filehandle={hex(_fh)})"
                f" [SEC_IMAGE={bool(_attrs & 0x1000000)} SEC_COMMIT={bool(_attrs & 0x8000000)} SEC_RESERVE={bool(_attrs & 0x4000000)}]")
            globals()['_last_sec_attrs'] = _attrs
        except Exception as e:
            log(f"NtCreateSection arg parse err: {e}")
        next_section_handle += 1
        sh = 0x31000 + next_section_handle
        if rcx: uc.mem_write(rcx, struct.pack('<Q', sh))
        log(f"NtCreateSection -> handle {hex(sh)}")
        ret = 0
    elif key == 'ntmapviewofsection':
        # SectionHandle rcx, ProcessHandle rdx, BaseAddress* r8, ZeroBits r9,
        # CommitSize st1, SectionOffset* st2, ViewSize* st3, ...
        # SESSION4-کشف۵: NtCreateSection با allocattrs=0x8000000=SEC_COMMIT آمد (نه SEC_IMAGE!)
        # پس این مپ، مپ دیتا (فایل خام خطی) است نه SEC_IMAGE. هر دو حالت پشتیبانی می‌شود:
        _attrs = globals().get('_last_sec_attrs', 0)
        if _attrs & 0x1000000:
            # SEC_IMAGE path (for future image mappings)
            vb = pgup(VIRT_PTR)
            size_img = pgup(SOI)
            virt_alloc(size_img, vb)
            try:
                uc.mem_write(vb, b'\x00' * size_img)
            except Exception:
                for _o in range(0, size_img, 0x10000):
                    uc.mem_write(vb + _o, b'\x00' * min(0x10000, size_img - _o))
            uc.mem_write(vb, data[:SOH])
            for (nm, va, vs, rs, rp, ch) in SECS:
                if rs:
                    uc.mem_write(vb + va, data[rp:rp+rs])
            for poff, pb in file_patches.items():
                _rva = fileoff_to_rva(poff)
                if _rva is not None:
                    try: uc.mem_write(vb + _rva, pb)
                    except Exception: pass
            VIRT_PTR = vb + size_img
            if r8: uc.mem_write(r8, struct.pack('<Q', vb))
            vs = read_stack_arg(uc, 3)
            if vs: uc.mem_write(vs, struct.pack('<Q', size_img))
            so = read_stack_arg(uc, 2)
            if so: uc.mem_write(so, struct.pack('<Q', 0))
            mapped_views.append((vb, True))
            log(f"NtMapViewOfSection -> SEC_IMAGE mapped (SizeOfImage={hex(size_img)} = {size_img:,} bytes) at {hex(vb)}")
            ret = 0
        else:
            # SEC_COMMIT data-file mapping: linear raw file (CORRECT for loader's integrity check)
            vb = pgup(VIRT_PTR)
            virt_alloc(len(data), vb)
            uc.mem_write(vb, data)   # THE REAL FILE CONTENT
            for poff, pb in file_patches.items():
                try: uc.mem_write(vb + poff, pb)
                except Exception: pass
            VIRT_PTR = vb + pgup(len(data))
            if r8: uc.mem_write(r8, struct.pack('<Q', vb))
            vs = read_stack_arg(uc, 3)
            if vs: uc.mem_write(vs, struct.pack('<Q', len(data)))
            so = read_stack_arg(uc, 2)
            if so: uc.mem_write(so, struct.pack('<Q', 0))
            mapped_views.append((vb, False))
            log(f"NtMapViewOfSection -> DATA mapped ({len(data):,} bytes) at {hex(vb)} [SEC_COMMIT, linear]")
            ret = 0
    elif key == 'ntunmapviewofsection':
        log(f"NtUnmapViewOfSection({hex(rcx)})")
        try:
            _vr = globals().get('_view_read_log', [])
            _vb = globals().get('_view_base', 0)
            log(f"    VIEW-READ summary: {len(_vr)} reads from SEC_IMAGE view @ {hex(_vb) if _vb else '?'}")
            if _vr:
                import collections as _cl
                _rips = _cl.Counter(r for (r, a, s) in _vr)
                for _r, _c in _rips.most_common(15):
                    log(f"      RIP {hex(_r)}: {_c} reads")
                # dump first 20 + last 20 reads with view offsets
                for (r, a, s) in (_vr[:20] + _vr[-20:]):
                    log(f"      RIP={hex(r)} view_off={hex(a - _vb)} size={s}")
                # where in the view? histogram by 1MB bucket
                _sz = globals().get('_view_size', 1)
                _buckets = _cl.Counter((a - _vb) // 0x100000 for (r, a, s) in _vr)
                for _b in sorted(_buckets):
                    log(f"      view MB bucket {_b} (file_off ~{hex(_b*0x100000)}): {_buckets[_b]} reads")
        except Exception as e:
            log(f"    view-read summary err: {e}")
        ret = 0
    elif key == 'ntquerysection':
        if r8:
            uc.mem_write(r8, b'\x00' * 0x38)
        ret = 0
    elif key == 'ntclose':
        ret = 0
    elif key == 'ntprotectvirtualmemory':
        # ProcessHandle=rcx, BaseAddress*=rdx, RegionSize*=r8, NewProtect=r9, OldProtect*=st1
        try:
            base0 = struct.unpack_from('<Q', uc.mem_read(rdx, 8), 0)[0]
            size0 = struct.unpack_from('<Q', uc.mem_read(r8, 8), 0)[0]
            do_protect(base0, size0, r9 & 0xFF)
            oldp = read_stack_arg(uc, 1)
            if oldp: uc.mem_write(oldp, struct.pack('<I', 0x40))
            log(f"NtProtectVirtualMemory(base={hex(base0)}, size={hex(size0)}, prot={hex(r9 & 0xFF)})")
        except Exception as e:
            log(f"NtProtectVirtualMemory err: {e}")
        ret = 0
    elif key == 'ntallocatevirtualmemory':
        # ProcessHandle=rcx, BaseAddress*=rdx, ZeroBits=r8, RegionSize*=r9, AllocType=st1, Prot=st2
        try:
            base0 = struct.unpack_from('<Q', uc.mem_read(rdx, 8), 0)[0]
            size0 = struct.unpack_from('<Q', uc.mem_read(r9, 8), 0)[0]
            a = virt_alloc(size0, base0)
            uc.mem_write(rdx, struct.pack('<Q', pg(a)))
            uc.mem_write(r9, struct.pack('<Q', pgup(size0)))
            log(f"NtAllocateVirtualMemory(base={hex(base0)}, size={hex(size0)}) -> {hex(pg(a))}")
        except Exception as e:
            log(f"NtAllocateVirtualMemory err: {e}")
        ret = 0
    elif key == 'ntfreevirtualmemory':
        ret = 0
    elif key == 'ntqueryinformationprocess':
        ret = handle_ntqueryinfo(uc, rdx & 0xFFFFFFFF, r8)
    elif key == 'ntquerysysteminformation':
        # (SystemInformationClass=rcx, SystemInformation=rdx, Length=r8, ReturnLength=r9)
        cls = rcx & 0xFFFFFFFF
        log(f"    NtQSI(cls={hex(cls)}, len={r8})")
        if cls == 0x23:   # SystemKernelDebuggerInformation
            if rdx: uc.mem_write(rdx, b'\x00\x01')   # Enabled=0, NotPresent=1
            if r9: uc.mem_write(r9, struct.pack('<Q', 2))
            ret = 0
        elif cls == 0x0B:  # SystemModuleInformation — kernel module list
            mods = [
                ('\SystemRoot\\system32\\ntoskrnl.exe', 0xFFFFF8024A000000, 0xF2B000),
                ('\SystemRoot\\system32\\hal.dll',     0xFFFFF8024B000000, 0x1D000),
                ('\SystemRoot\\system32\\kdcom.dll',   0xFFFFF8024B200000, 0x1A000),
                ('\SystemRoot\\System32\\drivers\\CLFS.SYS', 0xFFFFF8024B400000, 0x98000),
                ('\SystemRoot\\System32\\drivers\\ndis.sys', 0xFFFFF8024C000000, 0x138000),
            ]
            needed = 8 + len(mods) * 296
            if r9: uc.mem_write(r9, struct.pack('<Q', needed))
            if rdx and r8:
                blob = bytearray(min(r8, needed))
                struct.pack_into('<I', blob, 0, len(mods))
                off = 8
                for i, (path, base, size) in enumerate(mods):
                    if off + 296 > len(blob): break
                    struct.pack_into('<IQQIIHHHH', blob, off, 0, base, base, size, 0,
                                     i, i, 1, path.rfind('\\') + 1)
                    blob[off + 40:off + 40 + len(path)] = path.encode()
                    off += 296
                uc.mem_write(rdx, bytes(blob))
            ret = 0
        elif cls == 0x00:  # SystemBasicInformation
            if rdx:
                uc.mem_write(rdx, struct.pack('<IIIIIIII', 1, 0x1000, 0xFFFFFFF, 0x400000, 2, 1, 1, 0))
            if r9: uc.mem_write(r9, struct.pack('<Q', 0x2C))
            ret = 0
        else:
            if rdx and r8:
                uc.mem_write(rdx, b'\x00' * min(r8, 0x100))
            if r9: uc.mem_write(r9, struct.pack('<Q', min(r8 or 0x20, 0x100)))
            ret = 0
    elif key == 'wtssendmessagew':
        # hServer, SessionId, pTitle, TitleLength, pMessage, MessageLength, Style, Timeout, pResponse
        try:
            ret_addr = struct.unpack_from('<Q', uc.mem_read(rsp, 8), 0)[0]
            log(f"    *** WTSSendMessageW called FROM {hex(ret_addr)} (return addr) ***")
            # dump the calling context for offline analysis
            with open(OUT + '/wts_caller_context.bin', 'wb') as f:
                f.write(struct.pack('<Q', ret_addr))
                f.write(bytes(uc.mem_read(pg(ret_addr), 0x3000)))
        except Exception:
            pass
        try:
            title = read_wstr(r8)
            msg_ptr = struct.unpack_from('<Q', uc.mem_read(rsp + 0x28, 8), 0)[0]
            msg = read_wstr(msg_ptr)
            log(f"[WTS MESSAGE] title='{title}' msg='{msg}'")
        except Exception as e:
            log(f"WTSSendMessageW parse err: {e}")
        resp_ptr = struct.unpack_from('<Q', uc.mem_read(rsp + 0x48, 8), 0)[0] if rsp else 0
        if resp_ptr: uc.mem_write(resp_ptr, struct.pack('<I', 1))
        ret = 1
    elif key == 'wtssendmessagea':
        try:
            title = read_cstr(r8)
            msg_ptr = struct.unpack_from('<Q', uc.mem_read(rsp + 0x28, 8), 0)[0]
            msg = read_cstr(msg_ptr)
            log(f"[WTS MESSAGE] title='{title}' msg='{msg}'")
        except Exception as e:
            log(f"WTSSendMessageA parse err: {e}")
        ret = 1
    elif key == 'writefile':
        try:
            buf = bytes(uc.mem_read(rdx, r8))
            if rcx in (CONSOLE_HANDLE_OUT, CONSOLE_HANDLE_ERR):
                txt = buf.decode('utf-8', 'replace')
                log("[CONSOLE] " + txt.replace('\r', '').rstrip('\n'))
            else:
                log(f"API WriteFile(h={hex(rcx)}, {r8} bytes) data[:64]={buf[:64].hex()}")
        except Exception as e:
            log(f"WriteFile err {e}")
        if r9: uc.mem_write(r9, struct.pack('<Q', r8))
        ret = 1
    elif key == 'writeconsolea':
        try:
            log("[CONSOLE] " + bytes(uc.mem_read(rdx, r8)).decode('utf-8', 'replace'))
        except Exception: pass
        ret = 1
    elif key == 'writeconsolew':
        try:
            log("[CONSOLE] " + bytes(uc.mem_read(rdx, r8)).decode('utf-16le', 'replace'))
        except Exception: pass
        ret = 1
    elif key == 'isdebuggerpresent':
        ret = 0
    elif key == 'checkremotedebuggerpresent':
        if rdx: uc.mem_write(rdx, struct.pack('<I', 0))
        ret = 1
    elif key == 'gettickcount':
        ret = (_vt_ms[0] + 0x200000) & 0xFFFFFFFF   # SESSION4: coherent with KUSD TickCount
    elif key == 'gettickcount64':
        ret = _vt_ms[0] + 0x200000                  # SESSION4
    elif key == 'queryperformancefrequency':
        if rcx: uc.mem_write(rcx, struct.pack('<Q', 10_000_000))  # SESSION4: QPF=10MHz
        ret = 1
    elif key == 'queryperformancecounter':
        uc.mem_write(rcx, struct.pack('<Q', _vt_ms[0] * 10_000))  # SESSION4: 1ms = 10_000 ticks @10MHz — same rate as FILETIME
        ret = 1
    elif key == 'widechartomultibyte':
        src = bytes(uc.mem_read(r8, (r9 if r9 > 0 else 260)*2))
        s = src.decode('utf-16le', 'replace').split('\x00')[0]
        cb = struct.unpack_from('<Q', uc.mem_read(rsp + 0x30, 8), 0)[0] if rsp else 0
        dest = struct.unpack_from('<Q', uc.mem_read(rsp + 0x28, 8), 0)[0] if rsp else 0
        if dest and cb:
            uc.mem_write(dest, s.encode('utf-8') + b'\x00')
        ret = len(s) + 1
    elif key == 'multibytetowidechar':
        src = bytes(uc.mem_read(r8, (r9 if r9 > 0 else 260)))
        s = src.split(b'\x00')[0].decode('utf-8', 'replace')
        dest = struct.unpack_from('<Q', uc.mem_read(rsp + 0x28, 8), 0)[0] if rsp else 0
        cb = struct.unpack_from('<Q', uc.mem_read(rsp + 0x30, 8), 0)[0] if rsp else 0
        if dest and cb:
            uc.mem_write(dest, s.encode('utf-16le') + b'\x00\x00')
        ret = len(s) + 1
    elif key in ('createfilea',):
        nm = read_cstr(rcx)
        log(f"API CreateFileA('{nm}')")
        global next_fh
        next_fh += 1
        file_handles[next_fh] = nm
        ret = next_fh
    elif key == 'createfilew':
        nm = read_wstr(rcx)
        log(f"API CreateFileW('{nm}')")
        next_fh2 = 0x1000 + len(file_handles)
        file_handles[next_fh2] = nm
        ret = next_fh2
    elif key == 'readfile':
        if rcx == 0x10:  # stdin — feed fake license key
            feed = b"FAKE-KEY-1234567890\r\n"
            uc.mem_write(rdx, feed)
            if r9: uc.mem_write(r9, struct.pack('<Q', len(feed)))
            log("[CONSOLE-IN] fed fake license key")
            ret = 1
        else:
            if r9: uc.mem_write(r9, struct.pack('<Q', r8))
            ret = 1
    elif key == 'getfilesize':
        ret = 0
    elif key == 'closehandle':
        ret = 1
    elif key == 'setfilepointer':
        ret = 0
    elif key == 'findwindowa':
        ret = 0
    elif key == 'findwindoww':
        ret = 0
    elif key == 'iswow64process':
        if rdx: uc.mem_write(rdx, struct.pack('<I', 0))
        ret = 1
    elif key == 'certopenstore':
        global cert_store_counter
        cert_store_counter += 1
        try:
            prov = read_wstr(rcx) if rcx else ''
        except Exception:
            prov = ''
        log(f"CertOpenStore('{prov}') -> fake store {hex(0x55550000 + cert_store_counter)}")
        ret = 0x55550000 + cert_store_counter
    elif key == 'certenumcertificatesinstore':
        ret = 0  # NULL = end of enumeration (empty store)
    elif key == 'certenumphysicalstoresforcert':
        ret = 0
    elif key in ('certclosestore', 'certfreecertificatecontext', 'certfreecrlcontext',
                 'certfreectlcontext', 'cryptmsgclose', 'certfreecertificatechain'):
        ret = 1
    elif key == 'certgetcertificatecontextproperty':
        ret = 0
    elif key == 'certgetcertificatechain':
        ret = 0
    elif key in ('cryptprotectdata', 'cryptunprotectdata'):
        # pDataIn=rcx(DATA_BLOB*), ..., pDataOut=r9(DATA_BLOB*)
        try:
            cb, ptr = struct.unpack_from('<IQ', uc.mem_read(rcx, 16), 0)
            blob = bytes(uc.mem_read(ptr, cb)) if cb and ptr else b''
            out_ptr = HEAP_PTR
            HEAP_PTR = (HEAP_PTR + cb + 0x100) & ~0xF
            uc.mem_write(out_ptr, blob)
            uc.mem_write(r9, struct.pack('<IQ', cb, out_ptr))
            log(f"{key}({cb} bytes) -> passthrough copy")
        except Exception as e:
            log(f"{key} err: {e}")
            if r9: uc.mem_write(r9, struct.pack('<IQ', 0, 0))
        ret = 1
    elif key == 'wsastartup':
        if rdx: uc.mem_write(rdx, b'\x00' * 0x190)
        ret = 0
    elif key == 'socket':
        global socket_counter
        socket_counter += 1
        log(f"SOCKET(af={rcx}, type={rdx}, protocol={r8})")
        ret = 0x44440000 + socket_counter
    elif key == 'getaddrinfo':
        node = read_cstr(rcx) if rcx else ''
        svc = read_cstr(rdx) if rdx else ''
        log(f"*** GETADDRINFO('{node}', '{svc}') ***")
        if r9:
            base = HEAP_PTR
            HEAP_PTR += 0x200
            uc.mem_write(base, struct.pack('<IIIIIQQQ', 0, 2, 1, 6, 16, 0, base + 0x48, 0))
            uc.mem_write(base + 0x48, struct.pack('<HH4s8s', 2, 443, b'\x7f\x00\x00\x01', b'\x00' * 8))
            uc.mem_write(r9, struct.pack('<Q', base))
        ret = 0
    elif key == 'getaddrinfow':
        node = read_wstr(rcx) if rcx else ''
        svc = read_wstr(rdx) if rdx else ''
        log(f"*** GETADDRINFOW('{node}', '{svc}') ***")
        if r9:
            base = HEAP_PTR
            HEAP_PTR += 0x200
            uc.mem_write(base, struct.pack('<IIIIIQQQ', 0, 2, 1, 6, 16, 0, base + 0x48, 0))
            uc.mem_write(base + 0x48, struct.pack('<HH4s8s', 2, 443, b'\x7f\x00\x00\x01', b'\x00' * 8))
            uc.mem_write(r9, struct.pack('<Q', base))
        ret = 0
    elif key == 'freeaddrinfo':
        ret = 0
    elif key == 'connect':
        try:
            fam, port_raw = struct.unpack_from('<HH', uc.mem_read(rdx, 4), 0)
            ip = '.'.join(str(b) for b in uc.mem_read(rdx + 4, 4))
            port = struct.unpack('>H', port_raw.to_bytes(2, 'little'))[0] if False else ((port_raw & 0xFF) << 8) | (port_raw >> 8)
            log(f"*** CONNECT({ip}:{port}) ***")
        except Exception as e:
            log(f"connect parse err: {e}")
        ret = 0
    elif key == 'send':
        try:
            blob = bytes(uc.mem_read(rdx, min(r8, 400)))
            log(f"*** SEND({r8}B): {blob[:300]!r}")
        except Exception as e:
            log(f"send err {e}")
        ret = r8
    elif key == 'recv':
        log(f"RECV -> returning 0 (closed)")
        ret = 0
    elif key == 'closesocket':
        ret = 0
    elif key == 'wsagetlasterror':
        ret = 0
    elif key == 'select':
        ret = 0
    elif key == 'ioctlsocket':
        if r8: uc.mem_write(r8, struct.pack('<I', 0))
        ret = 0
    elif key == 'gethostname':
        uc.mem_write(rcx, b'EMU-PC\x00')
        ret = 0
    elif key in ('readconsolea', 'readconsolew'):
        key_feed = b"FAKE-KEY-1234567890\r\n"
        if key == 'readconsolew':
            key_feed = key_feed.decode().encode('utf-16le')
        uc.mem_write(rdx, key_feed)
        if r9:  # lpNumberOfCharsRead
            uc.mem_write(r9, struct.pack('<I', len("FAKE-KEY-1234567890")))
        ret = 1
    elif key == 'getnumberofconsoleinputevents':
        if rdx: uc.mem_write(rdx, struct.pack('<I', 0))
        ret = 1
    elif key == 'peekconsoleinputa':
        ret = 0
    elif key == 'setconsolemode':
        ret = 1
    elif key == 'getconsolemode':
        if rdx: uc.mem_write(rdx, struct.pack('<I', 3))
        ret = 1
    elif key == 'setconsoletextattribute':
        ret = 1
    elif key == 'setconsoleoutputcp':
        ret = 1
    elif key == 'getconsolecp':
        ret = 437
    elif key == 'getconsolewindow':
        ret = 0x77777777
    elif key == 'waitforsingleobject':
        ret = 0
    elif key == 'waitforsingleobjectex':
        ret = 0
    elif key == 'getcurrentprocessid':
        ret = 4012
    elif key == 'getcurrentthreadid':
        ret = 5104
    elif key == 'getcurrentprocess':
        ret = 0xFFFFFFFFFFFFFFFF
    elif key == 'getcomputernamea':
        uc.mem_write(rcx, b"EMU-PC\x00")
        ret = 6
    elif key == 'getcomputer Namew'.replace(' ', ''):
        uc.mem_write(rcx, "EMU-PC".encode('utf-16le') + b"\x00\x00")
        ret = 6
    elif key == 'getusernamew':
        uc.mem_write(rcx, "analyst".encode('utf-16le') + b"\x00\x00")
        ret = 7
    elif key == 'lstrlena':
        ret = len(read_cstr(rcx))
    elif key == 'lstrlenw':
        ret = len(read_wstr(rcx))
    elif key in ('getlasterror', 'setlasterror'):
        ret = 0
    elif key == 'rtladdfunctiontable':
        ret = 1
    elif key == 'flushinstructioncache':
        ret = 1
    elif key in ('virtualquery', 'virtualqueryex'):
        # VirtualQueryEx: rcx=hProcess, rdx=addr, r8=MBI*, r9=len
        if key == 'virtualqueryex':
            mq, mb, ml = rcx, rdx, r8
        else:
            mq, mb, ml = rcx, rdx, r8
        if mb:
            mbi = struct.pack('<QQQIIII', pg(mq), pg(mq), 0x40, 0, 0x1000, 0x1000, 0x40, 0x20000)
            uc.mem_write(mb, mbi[:48])
        ret = 48
    elif key == 'outputdebugstringa':
        try: log("[ODS] " + read_cstr(rcx))
        except Exception: pass
    elif key in ('createtoolhelp32snapshot',):
        ret = 0x77777
    elif key == 'process32firstw':
        # rcx=snapshot, rdx=PROCESSENTRY32W* — feed a fake MuMu process!
        try:
            name = "MuMuNxDevice.exe"
            uc.mem_write(rdx + 8, struct.pack('<I', 4242))        # th32ProcessID
            uc.mem_write(rdx + 24, struct.pack('<I', 100))        # th32ModuleID
            uc.mem_write(rdx + 28, struct.pack('<I', 6))          # cntThreads
            uc.mem_write(rdx + 32, struct.pack('<I', 1234))       # th32ParentProcessID
            uc.mem_write(rdx + 36, struct.pack('<i', 8))          # pcPriClassBase
            uc.mem_write(rdx + 44, name.encode('utf-16le') + b'\x00\x00')
            log(f"*** Process32FirstW -> FAKE TARGET '{name}' PID=4242 ***")
            ret = 1
        except Exception as e:
            log(f"Process32FirstW err: {e}")
            ret = 0
    elif key == 'process32nextw':
        ret = 0  # only one process
    elif key in ('process32first', 'process32next'):
        ret = 0
    elif key in ('module32firstw', 'module32nextw', 'module32first', 'module32next',
                 'thread32first', 'thread32next', 'heap32first', 'heap32next',
                 'heap32listfirst', 'heap32listnext'):
        ret = 0
    elif key == 'openprocess':
        log(f"API OpenProcess(access={hex(rcx)}, pid={r9})")
        ret = 0x88888
    elif key == 'writeprocessmemory':
        try:
            buf = bytes(uc.mem_read(rdx, r8))
            log(f"API WriteProcessMemory(remote={hex(rcx)}, size={hex(r8)}): {buf[:32].hex()}")
            open(OUT + '/injected_write_%d.bin' % api_calls.get(key, 0), 'wb').write(buf)
        except Exception as e:
            log(f"WPM err {e}")
        if r9: uc.mem_write(r9, struct.pack('<Q', r8))
        ret = 1
    elif key == 'createremotethread':
        log(f"API CreateRemoteThread(target={hex(rcx)}, start={hex(r9)})")
        ret = 0x99999
    else:
        if api_calls.get(key, 0) <= 3:
            log(f"API [default] {dll}!{name} -> 0")
        ret = 0
    uc.reg_write(UC_X86_REG_RAX, ret & 0xFFFFFFFFFFFFFFFF)

HEAP_PTR = HEAP_BASE

# ---- fill IAT from import descriptors ----
imp_rva = oh.DATA_DIRECTORY[1].VirtualAddress
log(f"IAT setup: import dir RVA {hex(imp_rva)}")
off = rva2off(imp_rva)
i = 0
while True:
    try:
        oft, ts, fc, name_rva, ft = struct.unpack_from('<IIIII', data, off + 20*i)
    except Exception:
        break
    if oft == 0 and name_rva == 0 and ft == 0:
        break
    no = rva2off(name_rva)
    dll = data[no:data.index(b'\x00', no)].decode('ascii', 'replace') if no else 'unknown'
    ensure_synth(dll)   # build the synth module FIRST so IAT stubs land inside its range
    thunk = oft or ft
    j = 0
    while True:
        to = rva2off(thunk + 8*j)
        if to is None: break
        v = struct.unpack_from('<Q', data, to)[0]
        if v == 0: break
        if v & (1 << 63):
            fname = f'ord#{v & 0xFFFF}'
        else:
            ho = rva2off(v)
            end = data.find(b'\x00', ho + 2)
            fname = data[ho+2:end].decode('ascii', 'replace')
        a = new_api(dll, fname)
        mu.mem_write(BASE + ft + 8*j, struct.pack('<Q', a))
        j += 1
    log(f"  imports: {dll} ({j} funcs)")
    i += 1
log(f"IAT filled. total APIs registered: {len(api_by_addr)}")

# ---- build core synthetic DLLs upfront (kernel32/ntdll/user32/wtsapi32...) ----
for core in ['kernel32.dll', 'ntdll.dll', 'user32.dll', 'wtsapi32.dll']:
    ensure_synth(core)

# ---- PEB Ldr module list (faithful-ish insurance) ----
def poke(addr, fmt, *vals):
    mu.mem_write(addr, struct.pack(fmt, *vals))

def build_ldr():
    entries = [('loader.exe', BASE, SOI)] + \
              [(k, b, m['image_size']) for k, b, m in
               [(k, b, [mm for mm in synth_meta if mm['base'] == b][0]) for k, b in synth_built.items()]]
    entry_base = LDR_ENTRIES
    name_base = LDR_NAMES
    list_heads = [LDR_HEAD + 0x10, LDR_HEAD + 0x20, LDR_HEAD + 0x30]  # load/memory/init order
    items = []
    nb = name_base
    bufs = b''
    for i, (nm, base, size) in enumerate(entries):
        eb = entry_base + i * 0x100
        w = nm.encode('utf-16le') + b'\x00\x00'
        bufs += w
        items.append((nm, base, size, eb, nb))
        nb += len(w)
    # link the three doubly-linked lists: head <-> e1 <-> e2 ... <-> head
    for li in range(3):
        head = list_heads[li]
        prev = head
        for (nm, base, size, eb, nb) in items:
            cur = eb + li * 0x10
            poke(prev, '<Q', cur)      # prev->Flink = cur
            poke(cur + 8, '<Q', prev)  # cur->Blink = prev
            prev = cur
        poke(prev, '<Q', head)                          # last->Flink = head
        poke(head + 8, '<Q', items[-1][3] + li * 0x10)  # head->Blink = last
    for i, (nm, base, size, eb, nb) in enumerate(items):
        poke(eb + 0x30, '<Q', base)        # DllBase
        poke(eb + 0x38, '<Q', 0)           # EntryPoint
        poke(eb + 0x40, '<Q', size)        # SizeOfImage
        poke(eb + 0x48, '<HHQ', len(nm)*2, len(nm)*2+2, nb)  # FullDllName
        poke(eb + 0x58, '<HHQ', len(nm)*2, len(nm)*2+2, nb)  # BaseDllName
    mu.mem_write(name_base, bufs)
    # PEB_LDR_DATA header
    poke(LDR_HEAD, '<I', 0x30)   # Length
    poke(LDR_HEAD + 4, '<I', 1)  # Initialized
build_ldr()

# ---------------- hooks ----------------
def hook_api(uc, address, size, ud):
    info = api_by_addr.get(address)
    if info is None: return
    dispatch(uc, info[0], info[1])
mu.hook_add(UC_HOOK_CODE, hook_api, begin=API_BASE, end=API_BASE + API_SIZE)

def hook_cpuid(uc, ud):
    leaf = uc.reg_read(UC_X86_REG_EAX)
    subleaf = uc.reg_read(UC_X86_REG_ECX)
    log(f"    CPUID leaf={hex(leaf)} sub={hex(subleaf)}")
    if leaf == 0:
        uc.reg_write(UC_X86_REG_EAX, 0x16)
        uc.reg_write(UC_X86_REG_EBX, 0x756E6547)
        uc.reg_write(UC_X86_REG_EDX, 0x49656E69)
        uc.reg_write(UC_X86_REG_ECX, 0x6C65746E)
    elif leaf == 1:
        uc.reg_write(UC_X86_REG_EAX, 0x000406E3)
        uc.reg_write(UC_X86_REG_EBX, 0x00000000)
        uc.reg_write(UC_X86_REG_ECX, 0x7FFEFBFF)  # hypervisor bit (31) = 0
        uc.reg_write(UC_X86_REG_EDX, 0xBFEBFBFF)
    elif leaf == 7:
        uc.reg_write(UC_X86_REG_EAX, 0)
        uc.reg_write(UC_X86_REG_EBX, 0x029C61AF)
        uc.reg_write(UC_X86_REG_ECX, 0)
        uc.reg_write(UC_X86_REG_EDX, 0x00000000)
    else:
        uc.reg_write(UC_X86_REG_EAX, 0)
        uc.reg_write(UC_X86_REG_EBX, 0)
        uc.reg_write(UC_X86_REG_ECX, 0)
        uc.reg_write(UC_X86_REG_EDX, 0)
    return 0
mu.hook_add(UC_HOOK_INSN, hook_cpuid, None, 1, 0, UC_X86_INS_CPUID)

def read_stack_arg(uc, idx):  # idx 1-based, args beyond r9
    rsp = uc.reg_read(UC_X86_REG_RSP)
    return struct.unpack_from('<Q', uc.mem_read(rsp + 0x28 + 8*(idx-1), 8), 0)[0]

def hook_syscall(uc, ud):
    num = uc.reg_read(UC_X86_REG_RAX)
    r10 = uc.reg_read(UC_X86_REG_R10)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8  = uc.reg_read(UC_X86_REG_R8)
    r9  = uc.reg_read(UC_X86_REG_R9)
    if num == 0x18:  # NtAllocateVirtualMemory(h, &base, zero, &size, type, prot)
        base0 = struct.unpack_from('<Q', uc.mem_read(rdx, 8), 0)[0]
        size0 = struct.unpack_from('<Q', uc.mem_read(r9, 8), 0)[0]
        a = virt_alloc(size0, base0)
        uc.mem_write(rdx, struct.pack('<Q', pg(a)))
        uc.mem_write(r9, struct.pack('<Q', pgup(size0)))
        uc.reg_write(UC_X86_REG_RAX, 0)
        log(f"SYSCALL NtAllocateVirtualMemory(size={hex(size0)}, base={hex(base0)}) -> {hex(pg(a))}")
    elif num == 0x50:  # NtProtectVirtualMemory(h, &base, &size, prot, &old)
        base0 = struct.unpack_from('<Q', uc.mem_read(rdx, 8), 0)[0]
        size0 = struct.unpack_from('<Q', uc.mem_read(r8, 8), 0)[0]
        do_protect(base0, size0, r9 & 0xFF)
        oldp = read_stack_arg(uc, 1)
        if oldp: uc.mem_write(oldp, struct.pack('<I', 0x40))
        uc.reg_write(UC_X86_REG_RAX, 0)
        log(f"SYSCALL NtProtectVirtualMemory(base={hex(base0)}, size={hex(size0)}, prot={hex(r9)})")
    elif num == 0x1E:  # NtFreeVirtualMemory
        uc.reg_write(UC_X86_REG_RAX, 0)
    elif num == 0x19:  # NtQueryInformationProcess
        cls = rdx & 0xFFFFFFFF
        st = handle_ntqueryinfo(uc, cls, r8)
        uc.reg_write(UC_X86_REG_RAX, st)
        log(f"SYSCALL NtQueryInformationProcess(cls={hex(cls)}) -> {hex(st & 0xFFFFFFFFFFFFFFFF)}")
    elif num == 0x36:  # NtQuerySystemInformation(class=r10, buf=rdx, len=r8, retlen=r9)
        cls = r10 & 0xFFFFFFFF
        if rdx:
            if cls == 0x23:  # SystemKernelDebuggerInformation
                uc.mem_write(rdx, b'\x00\x01')  # KernelDebuggerEnabled=0, NotPresent=1
            else:
                uc.mem_write(rdx, b'\x00' * min(r8 or 0x20, 0x100))
        if r9:
            uc.mem_write(r9, struct.pack('<Q', 2 if cls == 0x23 else 0x20))
        uc.reg_write(UC_X86_REG_RAX, 0)
        log(f"SYSCALL NtQuerySystemInformation(cls={hex(cls)}) -> handled")
    else:
        uc.reg_write(UC_X86_REG_RAX, 0)
        log(f"SYSCALL unhandled #{hex(num)} RIP={hex(uc.reg_read(UC_X86_REG_RIP))}")
mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

automap_bytes = 0

# ---------------- RDTSC defeat: block-hook patching rdtsc -> inc eax ----------------
import bisect
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
_md = Cs(CS_ARCH_X86, CS_MODE_64)
RDTSC_SITES = set()
_rdtsc_sorted = []
file_patches = {}   # file offset -> bytes (keep file views in sync with memory patches)

def addr_to_fileoff(addr):
    rva = addr - BASE
    for (nm, va, vs, rs, rp, ch) in SECS:
        if va <= rva < va + max(vs, rs) and rs:
            d = rva - va
            if d < rs:
                return rp + d
    return None

def sync_patch_to_fileviews(uc, addr, patch):
    """Apply the same patch to every mapped file view so integrity checks stay consistent."""
    off = addr_to_fileoff(addr)
    if off is None:
        return
    file_patches[off] = patch
    _rva = fileoff_to_rva(off)
    for _vb, _is_img in mapped_views:
        try:
            if _is_img:
                if _rva is not None:
                    uc.mem_write(_vb + _rva, patch)
            else:
                uc.mem_write(_vb + off, patch)
        except Exception:
            pass

def scan_rdtsc_sites():
    for (nm, va, vs, rs, rp, ch) in SECS:
        if not (ch & 0x20000000):
            continue
        blob = bytes(mu.mem_read(BASE + va, max(vs, rs) if rs else vs))
        start = 0
        while True:
            i = blob.find(b'\x0f\x31', start)
            if i == -1: break
            RDTSC_SITES.add(BASE + va + i)
            start = i + 1
        j = blob.find(b'\x0f\x01\xf9')  # rdtscp
        while j != -1:
            RDTSC_SITES.add(BASE + va + j)
            j = blob.find(b'\x0f\x01\xf9', j + 1)
    _rdtsc_sorted.extend(sorted(RDTSC_SITES))
    log(f"RDTSC candidate sites pre-scanned: {len(RDTSC_SITES)}")

# ---------------- RDTSC defeat: instruction hooks on EXECUTED sites only ----------------
import bisect
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
_md = Cs(CS_ARCH_X86, CS_MODE_64)
RDTSC_SITES = set()
_rdtsc_sorted = []
file_patches = {}
RDTSC_MODE = sys.argv[3] if len(sys.argv) > 3 else 'sites'   # off | recon | sites | trace
RDTSC_EXEC_LOG = os.path.join(HERE, 'rdtsc_executed_loader.txt')

# --- trace-mode: ring buffer of executed blocks ---
from collections import deque
_block_trace = deque(maxlen=256)

def hook_block_trace(uc, address, size, ud):
    _block_trace.append((address, size))

# --- recon-mode block hook: log every rdtsc site that actually EXECUTES ---
_recon_seen = set()

def hook_block_rdtsc_recon(uc, address, size, ud):
    if not _rdtsc_sorted:
        return
    i = bisect.bisect_left(_rdtsc_sorted, address)
    if i < len(_rdtsc_sorted) and _rdtsc_sorted[i] < address + size:
        # confirm precisely with capstone
        try:
            code = bytes(uc.mem_read(address, size))
            for ins in _md.disasm(code, address):
                if ins.mnemonic in ('rdtsc', 'rdtscp') and ins.address not in _recon_seen:
                    _recon_seen.add(ins.address)
                    with open(RDTSC_EXEC_LOG, 'a') as f:
                        f.write(hex(ins.address) + '\n')
        except Exception:
            pass

# --- sites-mode: per-site instruction hook (C-level filtering, fast) ---
tsc_value = [0x1_0000_0000]
_rdtsc_hits = []
_rdtsc_prev = {'addr': 0, 'n': 0}

def make_rdtsc_insn_hook():
    # SESSION4 FIX: two-tier delta (old flat +7 was 'impossibly fast' -> verdict agent per report v4)
    # adjacent sites (<0x200 bytes apart) = VMP calibration pair -> 15-90 cycles
    # distant sites / loop re-entry -> 2000-50000 cycles
    def hook(uc, address, size, ud):
        st = _rdtsc_prev
        st['n'] += 1
        if st['addr'] and abs(address - st['addr']) <= 0x200:
            delta = 15 + (st['n'] * 13) % 76
        else:
            delta = 2000 + (st['n'] * 131) % 48001
        st['addr'] = address
        tsc_value[0] += delta
        uc.reg_write(UC_X86_REG_EAX, tsc_value[0] & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_EDX, (tsc_value[0] >> 32) & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_RIP, address + size)   # size handles rdtsc(2) AND rdtscp(3)
        if len(_rdtsc_hits) < 400:
            _rdtsc_hits.append(address)
            log(f"    rdtsc #{len(_rdtsc_hits)} @ {hex(address)} tsc={hex(tsc_value[0])} d={delta}")
    return hook


def hook_unmapped(uc, access, address, size, value, ud):
    global automap_bytes
    if access == UC_MEM_FETCH_UNMAPPED:
        return False
    if automap_bytes > 256*1024*1024:
        return False
    a0 = pg(address); a1 = pgup(address + max(size, 8))
    try:
        uc.mem_map(a0, a1 - a0, UC_PROT_ALL)
        automap_bytes += a1 - a0
        log(f"automap {hex(a0)}-{hex(a1)} (access {access}, total {automap_bytes//(1024*1024)}MB)")
        return True
    except Exception:
        return False
mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

def hook_intr(uc, intno, ud):
    log(f"INT {intno} at RIP={hex(uc.reg_read(UC_X86_REG_RIP))}")
mu.hook_add(UC_HOOK_INTR, hook_intr)

OEP_HIT = False
def hook_oep(uc, ud):
    global OEP_HIT
    OEP_HIT = True
    log(f"*** OOP REACHED: RIP={hex(uc.reg_read(UC_X86_REG_RIP))} (entered .text) ***")
    dump_state('oep')
    uc.emu_stop()
mu.hook_add(UC_HOOK_BLOCK, hook_oep, begin=BASE + 0x1000, end=BASE + 0x1000 + 0xea1b7)

# ---------------- dump ----------------
def dump_state(tag):
    for (nm, va, vs, rs, rp, ch) in SECS:
        if vs == 0: continue
        try:
            blob = bytes(mu.mem_read(BASE + va, vs))
            fn = f"{OUT}/{tag}_{nm.strip('.').replace('.','_')}.bin"
            open(fn, 'wb').write(blob)
        except Exception as e:
            log(f"dump {nm}: {e}")
    try:
        full = bytes(mu.mem_read(BASE, SOI))
        open(f"{OUT}/{tag}_FULLIMAGE.bin", 'wb').write(full)
        log(f"dump_state('{tag}') complete: full image {len(full):,} bytes")
    except Exception as e:
        log(f"dump full: {e}")

def fill_ratio(rva, vsize):
    samples = [0x100, vsize//4, vsize//2, vsize*3//4, vsize-0x200]
    nz = 0; tot = 0
    for o in samples:
        if 0 <= o < vsize - 0x100:
            b = mu.mem_read(BASE + rva + o, 0x100)
            nz += sum(1 for x in b if x); tot += len(b)
    return nz / max(tot, 1)

# ---------------- run ----------------
mu.reg_write(UC_X86_REG_RSP, (STACK_TOP - 0x100) & ~0xF)
mu.mem_write((STACK_TOP - 0x100) & ~0xF, struct.pack('<Q', MAGIC_RET))
mu.reg_write(UC_X86_REG_RBP, 0)
mu.reg_write(UC_X86_REG_RCX, 0)
mu.reg_write(UC_X86_REG_RDX, 0)
mu.reg_write(UC_X86_REG_R8, 0)
mu.reg_write(UC_X86_REG_R9, 0)

log(f"\n{'='*70}\nStarting emulation: EP={hex(EP)}, image {hex(BASE)}+{hex(SOI)}")
apply_prot()
scan_rdtsc_sites()
if RDTSC_MODE == 'recon':
    log(f"RECON MODE: logging executed rdtsc sites to {RDTSC_EXEC_LOG}")
    mu.hook_add(UC_HOOK_BLOCK, hook_block_rdtsc_recon, begin=BASE, end=BASE + SOI)
elif RDTSC_MODE == 'trace':
    log("TRACE MODE: recording executed blocks (slow-ish)")
    mu.hook_add(UC_HOOK_BLOCK, hook_block_trace, begin=BASE, end=BASE + SOI)
    try:
        sites = [int(x, 16) for x in open(RDTSC_EXEC_LOG).read().split()]
    except FileNotFoundError:
        sites = []
    if not sites:
        sites = sorted(RDTSC_SITES)
    cb = make_rdtsc_insn_hook()
    for s in sites:
        mu.hook_add(UC_HOOK_CODE, cb, begin=s, end=s)
    log(f"TRACE MODE: + {len(sites)} rdtsc hooks")
elif RDTSC_MODE == 'sites':
    try:
        sites = [int(x, 16) for x in open(RDTSC_EXEC_LOG).read().split()]
    except FileNotFoundError:
        sites = []
    if not sites:
        log("SITES MODE: no executed-site file — falling back to all .vmp1 sites (SLOW)")
        sites = sorted(RDTSC_SITES)
    cb = make_rdtsc_insn_hook()
    for s in sites:
        mu.hook_add(UC_HOOK_CODE, cb, begin=s, end=s)
    log(f"SITES MODE: {len(sites)} per-site rdtsc hooks armed")
else:
    log("RDTSC MODE=off: running at full speed (timing checks may abort)")

ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 6
SECS_R = int(sys.argv[2]) if len(sys.argv) > 2 else 90
cur = EP
for r in range(ROUNDS):
    t0 = time.time()
    try:
        mu.emu_start(cur, MAGIC_RET, SECS_R * 1_000_000, 0)
        reason = 'timeout'
    except UcError as e:
        reason = f'UcError {e}'
    el = time.time() - t0
    log(f"round {r}: {el:.1f}s reason={reason} RIP={hex(mu.reg_read(UC_X86_REG_RIP))}")
    log(f"  .text fill={fill_ratio(0x1000, 0xea1b7):.2%}  .rdata fill={fill_ratio(0xec000, 0x5edda8):.2%}")
    log(f"  api_calls: {dict(sorted(api_calls.items(), key=lambda x: -x[1])[:12])}")
    if mu.reg_read(UC_X86_REG_RIP) == MAGIC_RET:
        log("returned to sentinel — stub returned (unusual)")
        dump_state('sentinel')
        break
    if OEP_HIT:
        break
    if 'UcError' in reason:
        log(f"  CRASH RIP={hex(mu.reg_read(UC_X86_REG_RIP))}")
        dump_state(f'crash_r{r}')
        break
    dump_state(f'round{r}')
    cur = mu.reg_read(UC_X86_REG_RIP)

dump_state('final')
log("API call summary:")
for k, v in sorted(api_calls.items(), key=lambda x: -x[1]):
    log(f"  {k}: {v}")
print("DONE")
