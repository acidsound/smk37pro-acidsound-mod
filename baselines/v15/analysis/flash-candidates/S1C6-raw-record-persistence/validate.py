#!/usr/bin/env python3
"""Validate the deterministic S1C6 raw-record persistence offline candidate."""
from __future__ import annotations

import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE = HERE / "build_s1c6_raw_record_persistence.py"

spec = importlib.util.spec_from_file_location("s1c6_builder", MODULE)
assert spec and spec.loader
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
builder.validate_existing()
