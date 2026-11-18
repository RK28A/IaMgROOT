"""Comparaison de deux (ou plusieurs) rapports de firmware."""
from __future__ import annotations

from typing import Any, Dict, List

from horizonlab.core.models import Envelope

COMPARED_PROPS_PREFIXES = ("ro.build.", "ro.product.", "ro.board.", "ro.vendor.build.", "ro.hardware",
                           "ro.vndk", "ro.treble", "ro.apex", "ro.crypto", "ro.secure", "ro.debuggable",
                           "ro.adb", "ro.boot", "ro.virtual_ab", "ro.zygote", "persist.", "ro.vros", "ro.ota")


def _dict_diff(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    ka, kb = set(a), set(b)
    return {
        "only_a": {k: a[k] for k in sorted(ka - kb)},
        "only_b": {k: b[k] for k in sorted(kb - ka)},
        "changed": {k: {"a": a[k], "b": b[k]} for k in sorted(ka & kb) if a[k] != b[k]},
        "same_count": sum(1 for k in ka & kb if a[k] == b[k]),
    }


def _norm_path(p: str) -> str:
    # system/system/... (system-as-root) et system/... sont alignés pour la comparaison.
    return p[7:] if p.startswith("system/system/") else p


def compare_firmware(a: Envelope, b: Envelope, max_items: int = 2000) -> Envelope:
    pa, pb = a.payload, b.payload
    props_a = {k: v for k, v in pa.get("props", {}).items() if k.startswith(COMPARED_PROPS_PREFIXES)}
    props_b = {k: v for k, v in pb.get("props", {}).items() if k.startswith(COMPARED_PROPS_PREFIXES)}
    files_a = {_norm_path(f["path"]): f for f in pa.get("inventory", {}).get("files", []) if "path" in f}
    files_b = {_norm_path(f["path"]): f for f in pb.get("inventory", {}).get("files", []) if "path" in f}
    only_a = sorted(set(files_a) - set(files_b))
    only_b = sorted(set(files_b) - set(files_a))
    changed = sorted(p for p in set(files_a) & set(files_b)
                     if files_a[p].get("sha256") and files_a[p].get("sha256") != files_b[p].get("sha256"))
    identical = sum(1 for p in set(files_a) & set(files_b)
                    if files_a[p].get("sha256") and files_a[p].get("sha256") == files_b[p].get("sha256"))

    elf_a = {_norm_path(e["path"]): e for e in pa.get("inventory", {}).get("elfs", [])}
    elf_b = {_norm_path(e["path"]): e for e in pb.get("inventory", {}).get("elfs", [])}
    needed_changes = []
    hardening_changes = []
    for p in sorted(set(elf_a) & set(elf_b)):
        na, nb = set(elf_a[p].get("needed") or []), set(elf_b[p].get("needed") or [])
        if na != nb:
            needed_changes.append({"path": p, "added": sorted(nb - na), "removed": sorted(na - nb)})
        ha, hb = elf_a[p].get("hardening") or {}, elf_b[p].get("hardening") or {}
        diff = {k: {"a": ha.get(k), "b": hb.get(k)} for k in set(ha) | set(hb) if ha.get(k) != hb.get(k)}
        if diff:
            hardening_changes.append({"path": p, "changes": diff})

    def by_type(p):
        return p.get("inventory", {}).get("by_type", {})

    kern = lambda p: [k.get("version") for k in p.get("kernel", []) if k.get("version")]  # noqa: E731
    sec_a = next((k.get("security_config") for k in pa.get("kernel", []) if k.get("security_config")), {})
    sec_b = next((k.get("security_config") for k in pb.get("kernel", []) if k.get("security_config")), {})
    apk_a = {x.get("package"): x for x in pa.get("inventory", {}).get("apks", []) if x.get("package")}
    apk_b = {x.get("package"): x for x in pb.get("inventory", {}).get("apks", []) if x.get("package")}
    parts_a = {x["name"]: x for x in pa.get("partitions", [])}
    parts_b = {x["name"]: x for x in pb.get("partitions", [])}

    payload = {
        "a": {"name": a.subject, "model": pa.get("model", {}).get("model_name"), "android": pa.get("android")},
        "b": {"name": b.subject, "model": pb.get("model", {}).get("model_name"), "android": pb.get("android")},
        "android": _dict_diff(pa.get("android") or {}, pb.get("android") or {}),
        "kernel": {"a": kern(pa), "b": kern(pb), "security_config": _dict_diff(sec_a or {}, sec_b or {})},
        "props": _dict_diff(props_a, props_b),
        "partitions": {"only_a": sorted(set(parts_a) - set(parts_b)), "only_b": sorted(set(parts_b) - set(parts_a)),
                       "common": sorted(set(parts_a) & set(parts_b))},
        "files": {"count_a": len(files_a), "count_b": len(files_b), "only_a_count": len(only_a),
                  "only_b_count": len(only_b), "changed_count": len(changed), "identical_count": identical,
                  "only_a": only_a[:max_items], "only_b": only_b[:max_items], "changed": changed[:max_items],
                  "truncated": max(len(only_a), len(only_b), len(changed)) > max_items},
        "by_type": {"a": by_type(pa), "b": by_type(pb)},
        "elf": {"needed_changes": needed_changes[:max_items], "hardening_changes": hardening_changes[:max_items]},
        "libraries": {
            "only_a": sorted(set(pa.get("inventory", {}).get("libraries", {}).get("providers", {})) -
                             set(pb.get("inventory", {}).get("libraries", {}).get("providers", {}))),
            "only_b": sorted(set(pb.get("inventory", {}).get("libraries", {}).get("providers", {})) -
                             set(pa.get("inventory", {}).get("libraries", {}).get("providers", {}))),
        },
        "apks": {"only_a": sorted(set(apk_a) - set(apk_b)), "only_b": sorted(set(apk_b) - set(apk_a)),
                 "version_changed": sorted(k for k in set(apk_a) & set(apk_b)
                                           if apk_a[k].get("version_code") != apk_b[k].get("version_code"))},
    }
    return Envelope(kind="firmware_comparison", subject=f"{a.subject} vs {b.subject}", payload=payload)


def compare_many(reports: List[Envelope]) -> List[Envelope]:
    return [compare_firmware(reports[i], reports[j]) for i in range(len(reports)) for j in range(i + 1, len(reports))]
