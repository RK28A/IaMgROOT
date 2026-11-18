"""Inventaire d'une arborescence : fichiers, empreintes, ELF, bibliothèques, APK/APEX, configs."""
from __future__ import annotations

import fnmatch
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from horizonlab.core.workspace import Workspace, sha256_file
from horizonlab.firmware import elfscan

log = logging.getLogger("horizonlab.firmware.inventory")

CONFIG_PATTERNS = [
    "*.rc", "*.prop", "build.prop", "fstab*", "*_contexts", "*file_contexts*", "*.cil", "sepolicy",
    "precompiled_sepolicy*", "*sepolicy*.sha256", "selinux_version", "*manifest*.xml",
    "*compatibility_matrix*.xml", "ueventd*.rc", "*.policy", "ld.config*.txt", "linker.config.pb",
    "public.libraries*.txt", "*permissions*.xml", "privapp-permissions*.xml", "sysconfig/*.xml",
    "*.conf", "media_codecs*.xml", "audio_policy*.xml", "*.json",
]
CONFIG_DIR_HINTS = ("etc/", "/etc", "init", "selinux", "vintf", "permissions", "sysconfig", "seccomp")
SKIP_DIRS = {".git", "__pycache__"}


def classify(rel: str, head: bytes) -> str:
    low = rel.lower()
    if head[:4] == b"\x7fELF":
        if low.endswith(".ko"):
            return "kernel_module"
        if ".so" in Path(low).name:
            return "shared_library"
        return "elf"
    if low.endswith(".apk"):
        return "apk"
    if low.endswith((".apex", ".capex")):
        return "apex"
    if low.endswith(".jar"):
        return "jar"
    if low.endswith((".odex", ".vdex", ".art", ".oat")):
        return "art_artifact"
    if low.endswith(".rc"):
        return "init_rc"
    if low.endswith(".xml"):
        return "xml"
    if low.endswith(".prop"):
        return "prop"
    if low.endswith(".cil") or "sepolicy" in low or low.endswith("_contexts"):
        return "selinux"
    if head[:2] == b"#!":
        return "script"
    return "other"


def iter_files(root: Path) -> Iterator[Tuple[Path, str]]:
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            yield p, p.relative_to(root).as_posix()


def is_config(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    if not any(h in "/" + rel for h in CONFIG_DIR_HINTS) and not name.endswith((".rc", ".prop")) \
            and name not in ("build.prop", "default.prop", "prop.default"):
        return False
    return any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, "*/" + p) for p in CONFIG_PATTERNS)


def read_symlink_table(root: Path) -> Dict[str, str]:
    """Liens symboliques : réels (os.readlink) + table produite par le lecteur ext4."""
    out: Dict[str, str] = {}
    for tsv in Path(root).rglob(".horizonlab_symlinks.tsv"):
        base = tsv.parent.relative_to(root).as_posix()
        for line in tsv.read_text(encoding="utf-8").splitlines():
            if "\t" in line:
                p, t = line.split("\t", 1)
                out[(base + p) if base != "." else p.lstrip("/")] = t
    return out


def build_inventory(root: Path, ws: Optional[Workspace] = None, hash_files: bool = True,
                    analyze_elf: bool = True, max_elf: Optional[int] = None,
                    progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    root = Path(root)
    files: List[Dict[str, Any]] = []
    elfs: List[Dict[str, Any]] = []
    apks: List[Dict[str, Any]] = []
    apexes: List[Dict[str, Any]] = []
    configs: List[str] = []
    by_type: Dict[str, Dict[str, int]] = {}
    symlinks: Dict[str, str] = read_symlink_table(root)
    total = 0
    from horizonlab.services import axml

    for i, (p, rel) in enumerate(iter_files(root)):
        if rel.endswith(".horizonlab_symlinks.tsv"):
            continue
        if p.is_symlink():
            try:
                symlinks[rel] = os.readlink(p)
            except OSError:
                pass
            continue
        try:
            size = p.stat().st_size
            with open(p, "rb") as f:
                head = f.read(8)
        except OSError as e:
            files.append({"path": rel, "error": str(e)})
            continue
        kind = classify(rel, head)
        rec: Dict[str, Any] = {"path": rel, "size": size, "type": kind}
        if hash_files:
            rec["sha256"] = sha256_file(p)
        files.append(rec)
        total += size
        t = by_type.setdefault(kind, {"count": 0, "bytes": 0})
        t["count"] += 1
        t["bytes"] += size
        if progress and i % 500 == 0:
            progress(f"{i} fichiers inventoriés")
        if kind in ("elf", "shared_library", "kernel_module") and analyze_elf and \
                (max_elf is None or len(elfs) < max_elf):
            try:
                e = elfscan.analyze_elf(p)
            except Exception as ex:  # noqa: BLE001
                e = {"error": f"{type(ex).__name__}: {ex}"}
            e["path"] = rel
            e["kind"] = kind
            e["sha256"] = rec.get("sha256")
            elfs.append(e)
        elif kind == "apk":
            try:
                a = axml.read_apk_manifest(p)
            except Exception as ex:  # noqa: BLE001
                a = {"error": f"{type(ex).__name__}: {ex}"}
            a["path"] = rel
            apks.append(a)
        elif kind == "apex":
            try:
                a = axml.read_apex_manifest(p)
            except Exception as ex:  # noqa: BLE001
                a = {"error": f"{type(ex).__name__}: {ex}"}
            a["path"] = rel
            apexes.append(a)
        if is_config(rel):
            configs.append(rel)
            if ws is not None:
                dest = ws.path("configs", rel)
                shutil.copy2(p, dest)
    libs = summarize_libraries(elfs)
    return {
        "root": root.as_posix(), "file_count": len(files), "total_bytes": total, "by_type": by_type,
        "files": files, "symlinks": symlinks, "elfs": elfs, "libraries": libs, "apks": apks,
        "apexes": apexes, "configs": configs,
    }


def partition_of(rel: str) -> str:
    parts = rel.split("/")
    if parts[0] == "system" and len(parts) > 1 and parts[1] in ("system_ext", "product", "vendor"):
        return parts[1]
    return parts[0]


def summarize_libraries(elfs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Bibliothèques natives : par partition, par ABI, et dépendances non résolues."""
    provided = {}
    for e in elfs:
        if e.get("kind") == "shared_library":
            name = e.get("soname") or e["path"].rsplit("/", 1)[-1]
            provided.setdefault(name, []).append(e["path"])
    needed_count: Dict[str, int] = {}
    for e in elfs:
        for n in e.get("needed", []) or []:
            needed_count[n] = needed_count.get(n, 0) + 1
    unresolved = sorted(n for n in needed_count if n not in provided)
    per_part: Dict[str, int] = {}
    per_abi: Dict[str, int] = {"64": 0, "32": 0}
    for e in elfs:
        if e.get("kind") == "shared_library":
            per_part[partition_of(e["path"])] = per_part.get(partition_of(e["path"]), 0) + 1
            if e.get("class") in (32, 64):
                per_abi[str(e["class"])] += 1
    most = sorted(needed_count.items(), key=lambda kv: (-kv[1], kv[0]))[:40]
    return {"count": sum(len(v) for v in provided.values()), "unique_names": len(provided),
            "per_partition": per_part, "per_abi": per_abi, "most_needed": most,
            "unresolved_needed": unresolved, "providers": {k: v for k, v in sorted(provided.items())}}
