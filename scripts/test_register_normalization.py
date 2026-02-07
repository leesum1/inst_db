#!/usr/bin/env python3
"""Test register normalization across all entries in a CSV mapping."""

import csv
from collections import Counter
from pathlib import Path

from inst_db.utils.registers import normalize_reg_name


def test_register_normalization(csv_path: Path, output_path: Path) -> int:
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    normalized = []
    for row in rows:
        reg_name = (row.get("reg_name") or "").strip()
        normalized_name = normalize_reg_name(reg_name)
        normalized.append((reg_name, normalized_name, reg_name != normalized_name))

    changed = [(orig, norm) for orig, norm, diff in normalized if orig and diff]
    empty = [orig for orig, _norm, _diff in normalized if not orig]

    print(f"Total rows: {len(rows)}")
    print(f"Empty reg_name: {len(empty)}")
    print(f"Changed by normalization: {len(changed)}")

    counter = Counter(norm for _orig, norm, _diff in normalized if norm)
    print("Top normalized names:")
    for name, count in counter.most_common(20):
        print(f"  {name:6s} {count}")

    print("\nSample changes:")
    for orig, norm in changed[:20]:
        print(f"  {orig:6s} -> {norm}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["reg_name", "normalized_name", "changed"])
        writer.writerows(normalized)
    print(f"\nWrote CSV: {output_path}")

    return 0


def main() -> int:
    csv_path = Path("tmp/arm64_regs.csv")
    output_path = Path("tmp/arm64_regs_normalized.csv")
    if not csv_path.exists():
        print(f"CSV not found: {csv_path}")
        return 1

    return test_register_normalization(csv_path, output_path)


if __name__ == "__main__":
    raise SystemExit(main())
