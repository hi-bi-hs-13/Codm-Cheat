# Real offsets — captured live 2026-09-23 06:02 (MITM --forward)

Source: `09_bypass_session4/offsets_capture_20260923_060211.json`
(cheat REAL + REAL key `7D74-...` → LOGIN_SUCCESS, expires `2026-10-18 15:10:04`)

## Verdict vs compiled defaults (unpacked DLL globals)
15 of 16 identical. ONLY delta: `typeinfo_character_model = 0x0` (server zeroes it).

## Full table (name -> value)
- typeinfo_engine = 0xE852F08 (== OFF0 camera root)
- typeinfo_weapon_fire_component_instant = 0xE868C18
- typeinfo_role = 0xE85E5A8
- typeinfo_role_base_character = 0xE85E580
- typeinfo_role_generic = 0xE851C80
- typeinfo_weapon_generic = 0xE851930
- typeinfo_item_resource_generic = 0xE851CC0
- typeinfo_character_model_generic = 0xE853E68
- typeinfo_item2inventory_generic = 0xE855C78
- typeinfo_role_pack_generic = 0xE85E5B0
- typeinfo_role_base_generic = 0xE85DD00
- typeinfo_weapon = 0xE854320
- typeinfo_item_resource = 0xE856940
- typeinfo_character_model = 0x0
- typeinfo_item2inventory = 0xE85DC68
- typeinfo_loadout_helper = 0xE8524F8
- offsets_signature = 66806da8b94699d0dbb5c17ce7ecf920c8a431f7f00b4393f714c88fbb6058cd

`fake_server.py` OFFSETS table aligned to this mapping (was zip-misaligned before).

## Camera chain (confirmed, ext.dll @0x180000000)
base+OFF0 → +0x78 → +0x00 → +0x70 → +0x150 → +0xC0 → +0x10 → +0xC0 (64B matrix).
NO klass/static_fields on this path. Pointer check: (ptr-0x1001) <= 0x7fffffffeffd.

## IPC record layout (confirmed LIVE 2026-09-23 14:10, loader heap)
Record 0xBB0 bytes, stride 0xBB0: FrameStart, Matrix, player, FrameEnd.
- +0x460: 7-byte marker ("player"/"Matrix"/...)
- +0x4A0: u64 id/object ptr | +0x4A8: u32 frame counter
- +0x4B0..: vec3 positions | +0x514: float dist | +0x518: u8 active
- Matrix record +0x55C: 16-float view matrix (row0 norm 1.0 verified live)
- player record +0x51A: name string ("[BOT]..." seen live)
- Self pawn is NOT listed (observer) — expect N-1 players, not N.
Push proven: records sit in LOADER heap while loader makes zero read
syscalls (ProcMon) — DLL writes them via WPM from MuMuNxDevice.

## Live-test procedure (bot match + memtap)
1. XAMPP Apache Stop, Windscribe Quit, server.bat → menu 1 (fake) [or 2 forward+real key]
2. cheat.bat (visible) → key → LICENSE VERIFIED → MuMu found
3. MuMu + CODM → bot match, cheat menu visible, ESP on
4. In match: `venv\Scripts\python.exe 09_bypass_session4\memtap.py --loop 5`
5. Send back: memtap_*.json (matrix OK? players count?) + cheat window text + any crash timing
