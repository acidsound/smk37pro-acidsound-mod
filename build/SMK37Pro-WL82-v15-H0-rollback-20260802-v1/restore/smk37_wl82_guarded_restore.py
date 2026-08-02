#!/usr/bin/env python3
"""Highly guarded SMK-37 Pro WL82 restore tool for the v15 H0 rollback bundle.

Only LoaderV2 Flash mutations implemented: 0xFB01 erase sector and 0xFB04 write
Flash. Both are contract-checked to the exact two 4 KiB sectors
{0x04000,0x62000}; writes are max 256 bytes and
carry CRC16-XMODEM little-endian. No reset, run-application, chip-erase, full
Flash write, or key commands are implemented. Default safe command is self-test.
"""
from __future__ import annotations

import argparse, hashlib, json, sys, tempfile, time
from pathlib import Path

EXPECTED_VENDOR = "WL82"
EXPECTED_PRODUCT = "UBOOT1.00"
FLASH_SIZE = 0x100000
SECTOR_SIZE = 0x1000
LOADER_ADDRESS = 0x1C02000
LOADER_ARGUMENT_SPI_NOR = 1
LOADER_BLOCK_SIZE = 512
OFFICIAL_LOADER_SIZE = 31232
OFFICIAL_LOADER_SHA256 = "9920e66626fc86b2db536050a4d23dec10c8d1081575553539835fd812276c27"
EXPECTED_DEVICE_TYPE = 0x03
EXPECTED_DEVICE_ID = 15425556
EXPECTED_FLASH_ID = 60256
IO_CHUNK_SIZE = 256
SECTORS = {0x04000, 0x62000}
STANDARD_INQUIRY_CDB = bytes([0x12, 0, 0, 0, 36, 0])
CMD_UBOOT_WRITE_MEMORY = 0xFB06
CMD_UBOOT_JUMP_MEMORY = 0xFB08
CMD_ERASE_SECTOR = 0xFB01
CMD_WRITE_FLASH = 0xFB04
CMD_READ_FLASH = 0xFD05
CMD_GET_ONLINE_DEVICE = 0xFC0A
CMD_READ_ID = 0xFC0B
CMD_GET_USB_BUFFER_SIZE = 0xFC14
ALLOWED = {CMD_UBOOT_WRITE_MEMORY, CMD_UBOOT_JUMP_MEMORY, CMD_ERASE_SECTOR, CMD_WRITE_FLASH, CMD_READ_FLASH, CMD_GET_ONLINE_DEVICE, CMD_READ_ID, CMD_GET_USB_BUFFER_SIZE}
CONFIRMS = [
    "I_UNDERSTAND_THIS_ERASES_EXACTLY_TWO_H0_SECTORS",
    "I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_H0_TARGET_HASHES",
    "RESTORE_OFFICIAL_V15_SECTORS_NOW",
]

class SafetyError(RuntimeError): pass

def sha256_bytes(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""): h.update(b)
    return h.hexdigest()
def crc16_xmodem(data: bytes, initial: int = 0) -> int:
    crc = initial & 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

def in_sector(address: int, length: int) -> bool:
    return any(s <= address and address + length <= s + SECTOR_SIZE for s in SECTORS)
def build_vendor_cdb(command: int, args: bytes = b"") -> bytes:
    if command not in ALLOWED: raise SafetyError(f"CDB 0x{command:04X} is not implemented")
    cdb = command.to_bytes(2, "big") + args
    if len(cdb) > 16: raise SafetyError("CDB too long")
    return cdb + b"\xFF" * (16 - len(cdb))
def validate_transfer_contract(cdb: bytes, data_out: bytes | None = None, data_in_length: int = 0) -> int | None:
    if data_out is not None and data_in_length: raise SafetyError("simultaneous data-in/out prohibited")
    if cdb == STANDARD_INQUIRY_CDB:
        if data_out is not None or data_in_length != 36: raise SafetyError("bad INQUIRY")
        return None
    if len(cdb) != 16: raise SafetyError("only 16-byte vendor CDBs accepted")
    cmd = int.from_bytes(cdb[:2], "big")
    if cmd not in ALLOWED: raise SafetyError(f"non-implemented CDB 0x{cmd:04X}")
    if cmd == CMD_ERASE_SECTOR:
        a = int.from_bytes(cdb[2:6], "big")
        if data_out is not None or data_in_length != 16 or a not in SECTORS or cdb[6:] != b"\xFF" * 10: raise SafetyError("erase contract mismatch")
    elif cmd == CMD_WRITE_FLASH:
        a = int.from_bytes(cdb[2:6], "big"); n = int.from_bytes(cdb[6:8], "big")
        if data_out is None or not 1 <= len(data_out) <= IO_CHUNK_SIZE or n != len(data_out) or cdb[8] != 0 or int.from_bytes(cdb[9:11], "little") != crc16_xmodem(data_out) or not in_sector(a, n) or (a // IO_CHUNK_SIZE) != ((a + n - 1) // IO_CHUNK_SIZE) or cdb[11:] != b"\xFF" * 5: raise SafetyError("write contract mismatch")
    elif cmd == CMD_READ_FLASH:
        a = int.from_bytes(cdb[2:6], "big"); n = int.from_bytes(cdb[6:8], "big")
        if data_out is not None or n != data_in_length or not 1 <= n <= IO_CHUNK_SIZE or a + n > FLASH_SIZE or cdb[8:] != b"\xFF" * 8: raise SafetyError("read contract mismatch")
    elif cmd == CMD_UBOOT_WRITE_MEMORY:
        a = int.from_bytes(cdb[2:6], "big"); n = int.from_bytes(cdb[6:8], "big")
        if data_out is None or not 1 <= len(data_out) <= LOADER_BLOCK_SIZE or n != len(data_out) or cdb[8] != 0 or int.from_bytes(cdb[9:11], "little") != crc16_xmodem(data_out) or not LOADER_ADDRESS <= a or a + n > LOADER_ADDRESS + OFFICIAL_LOADER_SIZE or cdb[11:] != b"\xFF" * 5: raise SafetyError("RAM loader write mismatch")
    elif cmd == CMD_UBOOT_JUMP_MEMORY:
        if data_out is not None or data_in_length != 16 or int.from_bytes(cdb[2:6], "big") != LOADER_ADDRESS or int.from_bytes(cdb[6:8], "big") != LOADER_ARGUMENT_SPI_NOR or cdb[8:] != b"\xFF" * 8: raise SafetyError("RAM loader jump mismatch")
    elif cmd in {CMD_GET_ONLINE_DEVICE, CMD_READ_ID, CMD_GET_USB_BUFFER_SIZE}:
        if data_out is not None or data_in_length != 16 or cdb[2:] != b"\xFF" * 14: raise SafetyError("loader info mismatch")
    return cmd

class RestoreClient:
    def __init__(self, transport): self.t = transport
    def inquiry(self):
        d = self.t.execute(STANDARD_INQUIRY_CDB, data_in_length=36)
        f = lambda s, n: d[s:s+n].decode("ascii", "strict").strip(" \x00")
        r = {"vendor": f(8, 8), "product": f(16, 16), "revision": f(32, 4)}
        if r["vendor"] != EXPECTED_VENDOR or r["product"] != EXPECTED_PRODUCT: raise SafetyError(f"unexpected identity {r}")
        return r
    def resp(self, cmd: int, args: bytes = b"") -> bytes:
        r = self.t.execute(build_vendor_cdb(cmd, args), data_in_length=16)
        if len(r) != 16 or int.from_bytes(r[:2], "big") != cmd: raise SafetyError(f"bad response for 0x{cmd:04X}")
        return r[2:]
    def upload_official_loader(self, loader: bytes) -> None:
        if len(loader) != OFFICIAL_LOADER_SIZE or sha256_bytes(loader) != OFFICIAL_LOADER_SHA256: raise SafetyError("official loader bytes are not locked expected loader")
        for off in range(0, len(loader), LOADER_BLOCK_SIZE):
            b = loader[off:off+LOADER_BLOCK_SIZE]
            args = (LOADER_ADDRESS + off).to_bytes(4, "big") + len(b).to_bytes(2, "big") + b"\0" + crc16_xmodem(b).to_bytes(2, "little")
            self.t.execute(build_vendor_cdb(CMD_UBOOT_WRITE_MEMORY, args), data_out=b)
        self.resp(CMD_UBOOT_JUMP_MEMORY, LOADER_ADDRESS.to_bytes(4, "big") + LOADER_ARGUMENT_SPI_NOR.to_bytes(2, "big"))
        time.sleep(0.5)
    def loader_info(self):
        size = int.from_bytes(self.resp(CMD_GET_USB_BUFFER_SIZE)[:4], "big")
        online = self.resp(CMD_GET_ONLINE_DEVICE); fid = int.from_bytes(self.resp(CMD_READ_ID)[:3], "big")
        device_id = int.from_bytes(online[2:6], "little")
        if not 256 <= size <= 0x10000 or online[0] != EXPECTED_DEVICE_TYPE or device_id != EXPECTED_DEVICE_ID or fid != EXPECTED_FLASH_ID:
            raise SafetyError(f"loader identity mismatch: buffer={size} type={online[0]} device_id={device_id} flash_id={fid}")
        return {"usb_buffer_size": size, "device_type": online[0], "device_id": device_id, "flash_id": fid}
    def read_flash(self, address: int, length: int) -> bytes:
        return self.t.execute(build_vendor_cdb(CMD_READ_FLASH, address.to_bytes(4, "big") + length.to_bytes(2, "big")), data_in_length=length)
    def erase_sector(self, address: int) -> None: self.resp(CMD_ERASE_SECTOR, address.to_bytes(4, "big"))
    def write_flash(self, address: int, data: bytes) -> None:
        args = address.to_bytes(4, "big") + len(data).to_bytes(2, "big") + b"\0" + crc16_xmodem(data).to_bytes(2, "little")
        self.t.execute(build_vendor_cdb(CMD_WRITE_FLASH, args), data_out=data)

def read_exact(client: RestoreClient, address: int, length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        n = min(IO_CHUNK_SIZE, length - len(out))
        block = client.read_flash(address + len(out), n)
        if len(block) != n: raise SafetyError(f"short Flash read at 0x{address + len(out):05X}")
        out.extend(block)
    return bytes(out)

def load_manifest(path: Path) -> dict:
    m = json.loads(path.read_text("utf-8")); addrs = {int(x["address"], 0) for x in m.get("sectors", [])}
    if m.get("format") != "smk37-v15-h0-forced-recovery-plan-v1" or addrs != SECTORS: raise SafetyError("manifest format or sector set mismatch")
    for x in m["sectors"]:
        if x.get("length") != SECTOR_SIZE or len(x.get("stock_sha256", "")) != 64 or len(x.get("expected_target_sha256", "")) != 64: raise SafetyError("bad manifest sector entry")
    return m
def validate_offline(prep: Path, manifest: dict) -> None:
    """Validate only immutable recovery inputs stored in this repository.

    The two full 1 MiB preflight dumps are acquired fresh from the target during
    every restore. They are intentionally not stored in Git.
    """
    for x in manifest["sectors"]:
        p = prep / "recovery-sectors" / x["stock_file"]
        if p.stat().st_size != SECTOR_SIZE or sha256_file(p) != x["stock_sha256"]: raise SafetyError(f"stock sector precondition failed: {p}")
def verify_current_target(client: RestoreClient, manifest: dict) -> None:
    for x in manifest["sectors"]:
        a = int(x["address"], 0); data = read_exact(client, a, SECTOR_SIZE)
        if len(data) != SECTOR_SIZE or sha256_bytes(data) != x["expected_target_sha256"]: raise SafetyError(f"target sector 0x{a:05X} does not match expected H0 hash")
def read_full_flash(client: RestoreClient) -> bytes:
    out = bytearray()
    for address in range(0, FLASH_SIZE, IO_CHUNK_SIZE): out.extend(client.read_flash(address, IO_CHUNK_SIZE))
    if len(out) != FLASH_SIZE: raise SafetyError("fresh dump was not exactly 1 MiB")
    return bytes(out)
def verify_outside_invariance(pre_flash: bytes, post_flash: bytes, manifest: dict) -> None:
    restored = {int(x["address"], 0) for x in manifest["sectors"]}
    for address in range(0, FLASH_SIZE, SECTOR_SIZE):
        if address not in restored and pre_flash[address:address+SECTOR_SIZE] != post_flash[address:address+SECTOR_SIZE]:
            raise SafetyError(f"post-restore outside-sector changed at 0x{address:05X}")
def restore_sectors(client: RestoreClient, prep: Path, manifest: dict, journal_path: Path | None = None) -> list[dict]:
    journal = []
    for x in sorted(manifest["sectors"], key=lambda y: int(y["address"], 0)):
        a = int(x["address"], 0); stock = (prep / "recovery-sectors" / x["stock_file"]).read_bytes()
        immediate = read_exact(client, a, SECTOR_SIZE)
        if sha256_bytes(immediate) != x["expected_target_sha256"]: raise SafetyError(f"immediate pre-erase H0 hash mismatch at 0x{a:05X}")
        client.erase_sector(a)
        erased = read_exact(client, a, SECTOR_SIZE)
        if erased != b"\xFF" * SECTOR_SIZE: raise SafetyError(f"erase-to-FF verify failed at 0x{a:05X}")
        for off in range(0, SECTOR_SIZE, IO_CHUNK_SIZE): client.write_flash(a + off, stock[off:off+IO_CHUNK_SIZE])
        readback = read_exact(client, a, SECTOR_SIZE); got = sha256_bytes(readback)
        if got != x["stock_sha256"]: raise SafetyError(f"readback verify failed at 0x{a:05X}")
        journal.append({"address": x["address"], "erased_to_ff": True, "write_chunks": 16, "readback_stock_sha256": got})
        if journal_path is not None:
            journal_path.write_text(json.dumps({"status": "in_progress", "completed_sectors": journal}, indent=2) + "\n", encoding="utf-8")
    return journal

class FakeTransport:
    def __init__(self, flash: bytes, identity_ok: bool = True, corrupt_after_write: int | None = None):
        self.flash = bytearray(flash); self.identity_ok = identity_ok; self.corrupt_after_write = corrupt_after_write; self.observed_vendor_cdbs = []; self.erased = []; self.writes = []
    def close(self): pass
    def execute(self, cdb: bytes, *, data_out: bytes | None = None, data_in_length: int = 0) -> bytes:
        cmd = validate_transfer_contract(cdb, data_out, data_in_length)
        if cmd is None:
            r = bytearray(36); r[8:16] = b"WL82    " if self.identity_ok else b"BAD     "; r[16:32] = b"UBOOT1.00       "; r[32:36] = b"1.00"; return bytes(r)
        self.observed_vendor_cdbs.append(cmd); a = int.from_bytes(cdb[2:6], "big")
        if cmd == CMD_GET_USB_BUFFER_SIZE: return cmd.to_bytes(2, "big") + (256).to_bytes(4, "big") + b"\0" * 10
        if cmd == CMD_GET_ONLINE_DEVICE: return cmd.to_bytes(2, "big") + bytes([EXPECTED_DEVICE_TYPE, 0]) + EXPECTED_DEVICE_ID.to_bytes(4, "little") + b"\0" * 8
        if cmd == CMD_READ_ID: return cmd.to_bytes(2, "big") + EXPECTED_FLASH_ID.to_bytes(3, "big") + b"\0" * 11
        if cmd in {CMD_UBOOT_WRITE_MEMORY}: return b""
        if cmd == CMD_UBOOT_JUMP_MEMORY: return cmd.to_bytes(2, "big") + b"\0" * 14
        if cmd == CMD_READ_FLASH:
            n = int.from_bytes(cdb[6:8], "big"); out = bytes(self.flash[a:a+n])
            if self.corrupt_after_write == a and any(self.corrupt_after_write <= wa < self.corrupt_after_write + SECTOR_SIZE for wa, _ in self.writes): out = bytes([out[0] ^ 1]) + out[1:]
            return out
        if cmd == CMD_ERASE_SECTOR: self.flash[a:a+SECTOR_SIZE] = b"\xFF" * SECTOR_SIZE; self.erased.append(a); return cmd.to_bytes(2, "big") + b"\0" * 14
        if cmd == CMD_WRITE_FLASH: self.flash[a:a+len(data_out)] = data_out; self.writes.append((a, len(data_out))); return b""
        raise AssertionError("unhandled fake command")

def self_test() -> int:
    if crc16_xmodem(b"123456789") != 0x31C3: raise AssertionError("CRC16-XMODEM vector failed")
    for bad in (0xFB00, 0xFB02, 0xFC12, 0xFC0D, 0xFE00):
        try: build_vendor_cdb(bad)
        except SafetyError: pass
        else: raise AssertionError(f"forbidden CDB accepted: 0x{bad:04X}")
    base = bytearray(b"\0" * FLASH_SIZE); manifest = {"format": "smk37-v15-h0-forced-recovery-plan-v1", "sectors": []}; stock = {}
    for i, a in enumerate(sorted(SECTORS)):
        target = bytes([i + 1]) * SECTOR_SIZE; st = bytes([0xA0 + i]) * SECTOR_SIZE; base[a:a+SECTOR_SIZE] = target; stock[a] = st
        manifest["sectors"].append({"address": f"0x{a:05x}", "length": SECTOR_SIZE, "stock_file": f"stock-{a:05x}.bin", "stock_sha256": sha256_bytes(st), "expected_target_sha256": sha256_bytes(target)})
    with tempfile.TemporaryDirectory() as td:
        prep = Path(td); (prep / "recovery-sectors").mkdir()
        for x in manifest["sectors"]: (prep / "recovery-sectors" / x["stock_file"]).write_bytes(stock[int(x["address"], 0)])
        client = RestoreClient(FakeTransport(bytes(base))); assert client.inquiry()["vendor"] == "WL82"; assert client.loader_info()["device_type"] == 3
        verify_current_target(client, manifest); restore_sectors(client, prep, manifest)
        fake = client.t
        if fake.erased != sorted(SECTORS) or len(fake.writes) != len(SECTORS) * 16 or any(n > 256 for _, n in fake.writes): raise AssertionError("erase/write scope failed")
        for mutate in (lambda: client.erase_sector(0), lambda: client.write_flash(0x4000, b"X" * 257), lambda: client.write_flash(0x5000, b"X")):
            try: mutate()
            except SafetyError: pass
            else: raise AssertionError("unsafe mutation accepted")
        try: restore_sectors(RestoreClient(FakeTransport(bytes(base), corrupt_after_write=0x04000)), prep, manifest)
        except SafetyError: pass
        else: raise AssertionError("readback failure did not stop")
        try: RestoreClient(FakeTransport(bytes(base), identity_ok=False)).inquiry()
        except SafetyError: pass
        else: raise AssertionError("identity failure did not stop")
    print("self-test PASS: FakeTransport erase/write/readback, CRC, CDB guards, failure cases")
    return 0

def run_restore(args) -> int:
    # Import the reviewed Windows SCSI transport from the derived read-only tool only when a real restore is explicitly requested.
    src = args.prep / "tools" / "windows_scsi_transport.py"
    import importlib.util
    spec = importlib.util.spec_from_file_location("readonly_transport", src); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    # Reuse only the reviewed Windows SCSI_PASS_THROUGH_DIRECT wrapper. Replace
    # its read-only transfer validator with this restore tool's stricter restore
    # contract so FB01/FB04 are allowed only for the audited sectors.
    mod.validate_transfer_contract = validate_transfer_contract
    manifest = load_manifest(args.manifest); validate_offline(args.prep, manifest)
    if args.confirm != CONFIRMS: raise SafetyError("missing exact explicit confirmations")
    loader = args.loader.read_bytes()
    evidence = args.prep / "restore" / f"restore-evidence-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}"
    evidence.mkdir(parents=True, exist_ok=False)
    progress_journal = evidence / "progress-journal.json"
    with mod.WindowsScsiTransport(args.device) as transport:
        client = RestoreClient(transport); identity = client.inquiry(); client.upload_official_loader(loader); info = client.loader_info()
        pre_a = read_full_flash(client); pre_b = read_full_flash(client)
        pre_sha = sha256_bytes(pre_a)
        if pre_a != pre_b: raise SafetyError("fresh double-dump preflight failed")
        (evidence / "pre-dump-a.bin").write_bytes(pre_a); (evidence / "pre-dump-b.bin").write_bytes(pre_b)
        verify_current_target(client, manifest)
        sector_journal = restore_sectors(client, args.prep, manifest, progress_journal)
        post = read_full_flash(client); verify_outside_invariance(pre_a, post, manifest)
        (evidence / "post-dump.bin").write_bytes(post)
        observed = sorted(set(transport.observed_vendor_cdbs))
    journal = {"format": "smk37-guarded-restore-journal-v1", "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "identity": identity, "loader_info": info, "fresh_pre_dump_sha256": pre_sha, "post_dump_sha256": sha256_bytes(post), "outside_restored_sectors_unchanged": True, "sectors": sector_journal, "observed_cdbs": [f"0x{x:04X}" for x in observed]}
    out = evidence / "restore-journal.json"
    out.write_text(json.dumps(journal, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"journal": str(out), "restored_sectors": [x["address"] for x in manifest["sectors"]], "observed_cdbs": journal["observed_cdbs"]}, indent=2))
    return 0

def parse(argv):
    ap = argparse.ArgumentParser(description=__doc__); sp = ap.add_subparsers(dest="cmd", required=True); sp.add_parser("self-test")
    rp = sp.add_parser("restore", help="DANGEROUS: real device restore, requires three exact --confirm values")
    root = Path(__file__).resolve().parents[1]
    rp.add_argument("--device", required=True); rp.add_argument("--prep", type=Path, default=root); rp.add_argument("--manifest", type=Path, default=root / "recovery-sectors" / "manifest.json"); rp.add_argument("--loader", type=Path, default=root / "assets" / "wl82loader.bin"); rp.add_argument("--confirm", action="append", default=[])
    return ap.parse_args(argv)
def main(argv) -> int:
    try:
        args = parse(argv)
        return self_test() if args.cmd == "self-test" else run_restore(args)
    except (SafetyError, OSError, json.JSONDecodeError, AssertionError) as e:
        print(f"SAFE STOP: {e}", file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main(sys.argv[1:]))
