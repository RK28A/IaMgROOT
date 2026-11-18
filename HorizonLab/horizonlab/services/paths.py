"""Correspondance chemins « appareil » (/system/bin/x) ↔ chemins de l'arborescence extraite."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

PARTITIONS = ("system", "vendor", "product", "system_ext", "odm", "vendor_dlkm", "odm_dlkm", "system_dlkm", "apex")


def tree_candidates(device_path: str) -> List[str]:
    """Chemins relatifs possibles dans l'arborescence pour un chemin appareil."""
    p = device_path.strip()
    if not p.startswith("/"):
        return [p]
    rel = p.lstrip("/")
    parts = rel.split("/", 1)
    first = parts[0]
    rest = parts[1] if len(parts) > 1 else ""
    cands = [rel]
    if first == "system":
        cands.append(f"system/system/{rest}")
    elif first in ("vendor", "product", "system_ext", "odm"):
        cands += [f"system/{rel}", f"system/system/{rel}"]
    elif first == "apex" and rest:
        cands += [f"system/apex/{rest}", f"system/system/apex/{rest}"]
    else:
        cands += [f"{x}_ramdisk/{rel}" for x in ("boot", "vendor_boot", "init_boot", "recovery")]
    return cands


def device_path(tree_rel: str) -> str:
    """Chemin appareil probable pour un chemin de l'arborescence."""
    rel = tree_rel.lstrip("/")
    for pre, rep in (("system/system/", "/system/"), ("system/vendor/", "/vendor/"),
                     ("system/product/", "/product/"), ("system/system_ext/", "/system_ext/")):
        if rel.startswith(pre):
            return rep + rel[len(pre):]
    for r in ("boot_ramdisk/", "vendor_boot_ramdisk/", "init_boot_ramdisk/", "recovery_ramdisk/"):
        if rel.startswith(r):
            return "/" + rel[len(r):]
    return "/" + rel


def resolve(root: Path, device_path_: str) -> Optional[str]:
    for c in tree_candidates(device_path_):
        if (Path(root) / c).is_file():
            return c
    return None


class LibraryIndex:
    """Index nom de bibliothèque → chemins, avec ordre de recherche proche du linker Android."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.by_name: Dict[str, List[str]] = {}
        for p in self.root.rglob("*.so*"):
            if p.is_file() and "/lib" in "/" + p.relative_to(self.root).as_posix():
                self.by_name.setdefault(p.name, []).append(p.relative_to(self.root).as_posix())
        for v in self.by_name.values():
            v.sort()

    def find(self, name: str, requester: str, is64: bool = True) -> Optional[str]:
        cands = self.by_name.get(name, [])
        if not cands:
            return None
        want = "lib64" if is64 else "lib/"
        dev = device_path(requester)
        part = dev.split("/")[1] if dev.count("/") > 1 else "system"

        def score(c: str) -> tuple:
            d = device_path(c)
            same_abi = want in c if is64 else ("/lib/" in "/" + c and "lib64" not in c)
            same_part = d.startswith(f"/{part}/")
            in_apex = "/apex/" in "/" + c
            in_hw = "/hw/" in c
            return (not same_abi, not same_part, not (d.startswith("/system/") or in_apex), in_hw, c)

        return sorted(cands, key=score)[0]
