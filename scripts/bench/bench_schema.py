#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Validate bench-compare result files against schema/result-v1.json.

Issue #2102 (epic #2101). The JSON Schema file is the single source of truth
for the result format; this module implements just the keyword subset it
uses (type, const, enum, pattern, required, properties, additionalProperties,
items, minItems, minimum, minLength) so validation needs nothing beyond the
Python standard library.

CLI (for tier authors):
    python3 scripts/bench/bench_schema.py FILE.json [FILE.json ...]
exits 0 when every file is valid, 1 otherwise.
"""
import json
import os
import re
import sys

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema", "result-v1.json")

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    # bool is an int subclass in Python, but not a JSON number.
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}

_schema_cache = None


def load_schema():
    global _schema_cache
    if _schema_cache is None:
        with open(SCHEMA_PATH, encoding="utf-8") as f:
            _schema_cache = json.load(f)
    return _schema_cache


def validate(value, schema, path="$"):
    """Return a list of human-readable errors (empty when valid)."""
    errs = []
    if "const" in schema and value != schema["const"]:
        errs.append(f"{path}: expected {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path}: {value!r} not one of {schema['enum']}")
    t = schema.get("type")
    if t is not None:
        if not _TYPES[t](value):
            errs.append(f"{path}: expected {t}, got {type(value).__name__}")
            return errs
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errs.append(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append(f"{path}: {value!r} does not match {schema['pattern']}")
    if _TYPES["number"](value) and "minimum" in schema and value < schema["minimum"]:
        errs.append(f"{path}: {value} < minimum {schema['minimum']}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errs.append(f"{path}: needs at least {schema['minItems']} item(s)")
        if "items" in schema:
            for i, item in enumerate(value):
                errs.extend(validate(item, schema["items"], f"{path}[{i}]"))
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errs.append(f"{path}: missing required field {key!r}")
        props = schema.get("properties", {})
        for key, sub in value.items():
            if key in props:
                errs.extend(validate(sub, props[key], f"{path}.{key}"))
            elif schema.get("additionalProperties", True) is False:
                errs.append(f"{path}: unknown field {key!r}")
    return errs


def validate_result(obj):
    return validate(obj, load_schema())


def load_result_file(path):
    """Load one result file (an object or an array of objects).

    Returns (valid_results, errors). Invalid entries are dropped and reported,
    so one bad row does not hide the rest of a tier's output.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        return [], [f"{path}: cannot load JSON: {e}"]
    items = data if isinstance(data, list) else [data]
    good, errs = [], []
    for i, item in enumerate(items):
        e = validate_result(item)
        if e:
            where = f"{path}[{i}]" if isinstance(data, list) else path
            errs.append(f"{where}: " + "; ".join(e))
        else:
            good.append(item)
    return good, errs


def main(argv):
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    bad = 0
    for p in argv:
        rs, errs = load_result_file(p)
        for e in errs:
            print(e)
        bad += len(errs)
        if not errs:
            print(f"{p}: OK ({len(rs)} result(s))")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
