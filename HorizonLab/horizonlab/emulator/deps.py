"""Résolution des dépendances natives selon un ordre de recherche proche du linker Android.

L'ordre réel dépend des espaces de noms du linker (ld.config.txt / linkerconfig) ; il est
ici approché par partition. Le rapport distingue :
  * ``resolved``               : trouvée dans les chemins de recherche de la partition ;
  * ``found_elsewhere``        : présente dans le sysroot mais hors de ces chemins (problème
                                  probable d'espace de noms sur le vrai casque) ;
  * ``missing``                : absente du sysroot.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from horizonlab.firmware import elfscan


def search_paths(sysroot: Path, binary_dev_path: str, is64: bool = True) -> List[str]:
    lib = "lib64" if is64 else "lib"
    apex = sorted(p.name for p in (Path(sysroot) / "apex").glob("*") if p.is_dir()) \
        if (Path(sysroot) / "apex").is_dir() else []
    system_paths = [f"/system/{lib}", f"/apex/com.android.runtime/{lib}/bionic"] + \
        [f"/apex/{a}/{lib}" for a in apex] + [f"/system_ext/{lib}", f"/product/{lib}"]
    vndk = [f"/apex/{a}/{lib}" for a in apex if a.startswith("com.android.vndk")]
    vendor_paths = [f"/odm/{lib}", f"/vendor/{lib}", f"/vendor/{lib}/hw", f"/vendor/{lib}/egl"] + vndk + \
        [f"/system/{lib}", f"/apex/com.android.runtime/{lib}/bionic"]
    if binary_dev_path.startswith(("/vendor/", "/odm/")):
        return vendor_paths
    return system_paths


class DependencyResolver:
    def __init__(self, sysroot: Path, max_depth: int = 12):
        self.sysroot = Path(sysroot)
        self.max_depth = max_depth
        self._index: Optional[Dict[str, List[str]]] = None

    def _all_libs(self) -> Dict[str, List[str]]:
        if self._index is None:
            self._index = {}
            for p in self.sysroot.rglob("*.so*"):
                if p.is_file():
                    self._index.setdefault(p.name, []).append("/" + p.relative_to(self.sysroot).as_posix())
        return self._index

    def resolve(self, binary_dev_path: str) -> Dict[str, Any]:
        host = self.sysroot / binary_dev_path.lstrip("/")
        if not host.exists():
            return {"binary": binary_dev_path, "error": "binaire absent du sysroot"}
        info = elfscan.analyze_elf(host)
        is64 = info.get("class", 64) == 64
        result: Dict[str, Any] = {"binary": binary_dev_path, "interpreter": info.get("interpreter"),
                                  "machine": info.get("machine"), "resolved": {}, "found_elsewhere": {},
                                  "missing": [], "tree": []}
        interp = info.get("interpreter")
        if interp:
            ip = self.sysroot / interp.lstrip("/")
            result["interpreter_present"] = ip.exists()
        queue = [(binary_dev_path, n, 1) for n in info.get("needed") or []]
        seen = set()
        while queue:
            req, name, depth = queue.pop(0)
            result["tree"].append({"from": req, "needs": name, "depth": depth})
            if name in seen:
                continue
            seen.add(name)
            found = None
            for d in search_paths(self.sysroot, req if req.startswith("/vendor") else binary_dev_path, is64):
                cand = self.sysroot / d.lstrip("/") / name
                if cand.exists():
                    found = f"{d}/{name}"
                    break
            if found:
                result["resolved"][name] = found
                if depth < self.max_depth:
                    sub = elfscan.analyze_elf(self.sysroot / found.lstrip("/"))
                    for n in sub.get("needed") or []:
                        queue.append((found, n, depth + 1))
            elif name in self._all_libs():
                result["found_elsewhere"][name] = self._all_libs()[name]
            else:
                result["missing"].append(name)
        result["runnable_prediction"] = (not result["missing"] and not result["found_elsewhere"]
                                         and result.get("interpreter_present", True))
        return result
