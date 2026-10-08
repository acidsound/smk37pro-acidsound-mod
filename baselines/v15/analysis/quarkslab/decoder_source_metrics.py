#!/usr/bin/env python3
"""Count and hash pi32v2 SLEIGH constructors for two prepared modules."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def module_metrics(module: Path) -> dict[str, object]:
    language_dir = module / "data" / "languages"
    files = sorted(
        [language_dir / "pi32v2.slaspec", *language_dir.glob("pi32v2_ins_*.sinc")]
    )
    details = []
    total_constructors = 0
    total_lines = 0
    for path in files:
        text = path.read_text(errors="replace")
        lines = text.splitlines()
        constructors = sum(1 for line in lines if re.match(r"^\s*:", line))
        total_constructors += constructors
        total_lines += len(lines)
        details.append(
            {
                "file": path.name,
                "lines": len(lines),
                "constructors": constructors,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    sla = language_dir / "pi32v2.sla"
    return {
        "constructors": total_constructors,
        "source_lines": total_lines,
        "compiled_sla_sha256": hashlib.sha256(sla.read_bytes()).hexdigest(),
        "files": details,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quarkslab-module", type=Path, required=True)
    parser.add_argument("--kagaimiq-module", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {
        "quarkslab": module_metrics(args.quarkslab_module),
        "kagaimiq-patched": module_metrics(args.kagaimiq_module),
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
