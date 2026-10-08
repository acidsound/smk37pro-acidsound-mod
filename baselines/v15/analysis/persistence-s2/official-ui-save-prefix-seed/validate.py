#!/usr/bin/env python3
"""Validate official-ui-save-prefix-seed investigation artifacts."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent


def shaf(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)
    print("PASS\t" + msg)


def load_analyzer():
    path = HERE / "analyze_official_ui_save_prefix_seed.py"
    spec = importlib.util.spec_from_file_location("official_ui_save_prefix_seed", path)
    req(spec is not None and spec.loader is not None, "load analyzer module spec")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def main() -> None:
    mod = load_analyzer()
    ev = mod.build_evidence()
    report = mod.render_report(ev)
    evidence_text = mod.json.dumps(ev, indent=2, sort_keys=True) + "\n"
    validation_text = "\n".join(ev["checks"] + ["RESULT\tPASS"]) + "\n"

    req((HERE / "evidence.json").read_text(encoding="utf-8") == evidence_text, "evidence.json deterministic")
    req((HERE / "report.md").read_text(encoding="utf-8") == report, "report.md deterministic")
    req((HERE / "validation.txt").read_text(encoding="utf-8") == validation_text, "validation.txt deterministic")
    req(ev["decision"] == "BLOCK_DETERMINISTIC_SAFE_HOST_SENDER", "decision blocks deterministic sender")
    req(ev["safe_sender_emitted"] is False, "no unsafe live sender emitted")
    req(ev["records_96_111"][0]["record_index"] == 96, "first target record 96")
    req(ev["records_96_111"][-1]["record_index"] == 111, "last target record 111")
    req(ev["records_96_111"][0]["raw_storage_rel"] == "0x7d20", "record 96 storage offset")
    req(ev["records_96_111"][-1]["raw_physical_offset"] == "0x0fc6ad", "record 111 physical offset")
    req("Stock SAVE ignores" in "\n".join(ev["blockers"]), "SAVE ignored-return blocker captured")
    req("product_sysex_alone" in ev["normal_firmware_capability"], "product SysEx capability captured")
    req("stock_ui_save" in ev["normal_firmware_capability"], "stock UI SAVE capability captured")

    expected = []
    for name in ["analyze_official_ui_save_prefix_seed.py", "evidence.json", "report.md", "validate.py", "validation.txt"]:
        expected.append(f"{shaf(HERE / name)}  {name}")
    req((HERE / "SHA256SUMS").read_text(encoding="utf-8") == "\n".join(expected) + "\n", "SHA256SUMS current")
    print("RESULT\tPASS")


if __name__ == "__main__":
    main()
