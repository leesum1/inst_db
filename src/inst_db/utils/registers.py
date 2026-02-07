"""Register name normalization utilities."""

import re
from typing import Optional


_W_REG_RE = re.compile(r"^w(\d+)$")
_X_REG_RE = re.compile(r"^x(\d+)$")
_V_REG_RE = re.compile(r"^[bhsdqv](\d+)$")
_Z_REG_RE = re.compile(r"^z(\d+)$")
_P_REG_RE = re.compile(r"^p(\d+)$")
_ZA_VIEW_RE = re.compile(r"^za[bdhqsv](\d+)$")
_ZA_SLICE_RE = re.compile(r"^za[bdhqsv]\d+$")


def normalize_reg_name(reg_name: Optional[str]) -> Optional[str]:
    """Normalize register aliases to a canonical 64-bit form.

    Rules:
    - wN -> xN
    - wsp -> sp
    - wzr -> xzr
    - fp -> x29
    - lr -> x30
    - b/h/s/d/q/vN -> vN
    - zN unchanged
    - pN unchanged
    - za* views (zaq/zas/zah/zad/zab + indexed slices) -> za
    - sp/xzr/pc unchanged
    - other names are lowercased
    """
    if reg_name is None:
        return None

    name = reg_name.strip().lower()
    if not name:
        return name

    if name == "wsp":
        return "sp"
    if name == "wzr":
        return "xzr"
    if name == "fp":
        return "x29"
    if name == "lr":
        return "x30"
    if name == "sp" or name == "xzr" or name == "pc":
        return name

    match = _W_REG_RE.match(name)
    if match:
        return f"x{match.group(1)}"

    match = _V_REG_RE.match(name)
    if match:
        return f"v{match.group(1)}"

    match = _Z_REG_RE.match(name)
    if match:
        return name

    match = _P_REG_RE.match(name)
    if match:
        return name

    if name == "za":
        return name

    if _ZA_VIEW_RE.match(name) or _ZA_SLICE_RE.match(name):
        return "za"

    match = _X_REG_RE.match(name)
    if match:
        return name

    return name
