# EXT.MEM Camera Chain Research — 2026-09-23 (single file, all findings)

Target: `ext_mem_20260923_130131.dll` (10,670,080 B, imagebase file `0x7fffb8700000`, friend base `0x180000000`)
IDA MCP: `127.0.0.1:13337`, pid 17196, `ext_mem_20260923_130131.dll.i64`, hexrays ready.
Note: MCP `lookup_funcs`/`disasm`/`get_bytes` on `0x18000a4c0` + IDA-VA form both fail/zeros —
file sections `.text/.rdata` have raw=0 (memory-dump layout, only `.vmp1` has raw data).
Ground truth therefore = friend's dumps in `iacpc/06_asm_disassembly/` (verified by reading).

## 1. chain_A (asm_chain.txt:2-56, func 0x1800391b0) — p4 discovery
```
rdx = [rip+0x1800d2460] + [rip+0x1800d4388]   ; cheat globals (server OFF0 typeinfo)
call 0x18000a630                              ; memread helper -> [rsp+0x20]
check (ptr-0x1001) <= 0x7fffffffeffd  (else fail)
rdx += 0x78 ; read ; check
(no +0x00 step — direct)
rdx += 0x70 ; read ; check -> return rax (=p4)
```
So chain_A = global → +0x78 → +0x70 = p4. NOT +0x78→+0x00→+0x70.

## 2. chain_B (asm_chain.txt:58-96, func 0x180039100) — cam1/cam2
```
rcx = p4 (input)
check (rcx-0x1001); lea rdx,[rcx+0x150]; read -> cam1; check
add rdx,0xC0; read -> cam2; check -> return cam2
```
No klass, no static_fields anywhere in either chain.

## 3. Matrix (asm_matrix_xref.txt:70-114, caller near 0x180026870)
```
call chain_A -> check; call chain_B -> check
lea rdx,[rax+0x10]; call 0x18000a630 -> mat; check
zero [rbp+0x200..0x230]; add rdx,0xC0; call 0x18000a4c0  ; 64B copy (4 xmm)
```
Full cheat chain: p4 → +0x150 cam1 → +0xC0 cam2 → +0x10 mat → 64B copy from mat+0xC0.

## 4. THE BUG WE HAD (live log proof)
`IsValidPtr = (ptr-0x1001)<=0x7fffffffeffd` PASSES klass pointers too:
`pCam=0x400002DFB490` (libunity mapping) passes, heap is `0x72..0x7F`.
Our old code trusted `Base+0x118` p4 + `+0x150` blindly → klass → `+0xC0` read
string data ("Spec...", "E\0N\0T") → Matrix Candidates=0 → no ESP boxes.
Fix (mumu-dll camera_manager.cpp ChainR, build 2026-09-23):
- p4 candidates: `Base+0x118` first, then brute `Base+0x00..0x200` (dedup, 33 max)
- cam1 selection requires HEAP range (`>=0x700000000000`, not just IsValidPtr);
  `+0x150` priority, then scan `pc+0x00..0x200`
- cam2/mat require heap range too; matrix = 64B `GameRead(mat+0xC0)`
- Old klass/static_fields path DELETED entirely (cheat never uses it)

## 5. OFF0 / server offsets (friend sniffing, verified)
engine OFF0 `0xE852F08` == compiled default ✅; other 14 typeinfos match ✅;
only `character_model = 0x0` differs (server sends zero → DLL must resolve locally/skip).
Conclusion: chain root is CORRECT, bug was cam1 selection, not OFF0.

## 6. Resolver question — SETTLED
Static_fields resolver `0x18002c438` only validates pre-resolved TypeInfo pointers
(validator `0x18002bb30`) for configs (Weapon/Role). NO klass+0xB8 reads for camera
anywhere in DLL. Deleted from our code.

## 7. Player record IPC (asm_player_record.txt, 447 lines, 19KB)
marker 7B @ +0x460, id @ +0x4A0, distance float @ +0x514, active byte @ +0x518.
`players=0` = genuinely empty frame (unfocused), NOT parser bug. Our IsInMatch
(HP>10 + valid pos) already handles this.

## 8. Menu dispatch (asm_ipc_dispatch_a.txt)
String-compare Enable/Disable only. Not useful for chain debug. Ignored.

## 9. Our DLL status (mumu-dll.dll 576,000 B, build 2026-09-23 13:25)
- Pawn logic untouched (6 pawns via `0x160`, HP/pos correct)
- ChainR rewritten as above; step-logging `[STEP]` + `[CR]` markers (unthrottled)
- Pending: user injects via Extreme Injector into MuMuNxDevice.exe, then read `[CR]` log

## 10. Live matrix record (memtap, 2026-09-23 — friend sniffing)
- Matrix record @ +0x55C: row0 [0.022, -0.268, -0.963], norm = sqrt(0.000484+0.071824+0.927369)
  = sqrt(0.999677) ≈ 0.9998 ≈ 1.0 ✅ valid rotation basis
- row3 (camera pos): [-14.669, 16.839, 69.0]
- Player list shows ONLY bot ([BOT]..., dist=100.0); self absent = observer not listed.
  So players=1 is CORRECT here, not 2. (Our game-heap pawn list includes self → 2;
  their memtap IPC list excludes observer → 1. Both consistent.)
- Final record layout (0xBB0): marker +0x460 → id +0x4A0 → frame counter +0x4A8 →
  positions → dist float +0x514 → name +0x51A → Matrix record +0x55C
- WPM push PROVEN: records live in loader memory while loader did zero reads
  (ProcMon) → DLL pushes them from inside MuMuNxDevice via WPM. IPC channel closed.
- Impact on our validator: rotation-row norm≈1.0 CONFIRMS our existing unit-basis
  check (`camera_manager.cpp` ValidateMatrixMultiPawn: 2 of 3 basis in [0.7,1.3]).
  No code change needed — 0.9998 already passes. Do NOT tighten: live matrices vary.
