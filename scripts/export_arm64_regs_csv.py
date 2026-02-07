#!/usr/bin/env python3
"""Export ARM64 register mapping to CSV."""

import csv
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone import arm64_const


def export_arm64_regs_csv(output_path: Path) -> int:
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    regs = []
    for name, value in arm64_const.__dict__.items():
        if name.startswith("ARM64_REG_") and isinstance(value, int):
            regs.append((value, name, cs.reg_name(value)))

    seen = set()
    rows = []
    for reg_id, const_name, reg_name in sorted(regs, key=lambda x: x[0]):
        if reg_id in seen:
            continue
        seen.add(reg_id)
        rows.append((reg_id, const_name, reg_name))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["reg_id", "const_name", "reg_name"])
        writer.writerows(rows)

    return len(rows)


def main() -> None:
    output_path = Path("tmp/arm64_regs.csv")
    count = export_arm64_regs_csv(output_path)
    print(f"Wrote {count} rows to {output_path}")


if __name__ == "__main__":
    main()
