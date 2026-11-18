"""Manifestes VINTF (HAL déclarées) et fichiers de permissions Android."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from horizonlab.services.sepolicy import parse_contexts_line  # noqa: F401  (réexport pratique)


def _text(e, tag, default=None):
    x = e.find(tag)
    return x.text.strip() if x is not None and x.text else default


def parse_vintf_manifest(path: Path, rel: str) -> Dict[str, Any]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        return {"file": rel, "error": str(e), "hals": []}
    if root.tag not in ("manifest", "compatibility-matrix"):
        return {"file": rel, "hals": [], "ignored": True}
    hals = []
    for hal in root.findall("hal"):
        fmt = hal.get("format", "hidl")
        name = _text(hal, "name", "?")
        versions = [v.text.strip() for v in hal.findall("version") if v.text]
        instances = []
        for fq in hal.findall("fqname"):
            if fq.text:
                instances.append(fq.text.strip())
        for itf in hal.findall("interface"):
            iname = _text(itf, "name", "?")
            for inst in itf.findall("instance"):
                if inst.text:
                    instances.append(f"{iname}/{inst.text.strip()}")
        hals.append({"format": fmt, "name": name, "versions": versions, "transport": _text(hal, "transport"),
                     "instances": instances, "optional": hal.get("optional"),
                     "updatable_via_apex": hal.get("updatable-via-apex")})
    return {"file": rel, "kind": root.tag, "type": root.get("type"), "target_level": root.get("target-level"),
            "hals": hals}


def find_vintf(root: Path) -> List[Dict[str, Any]]:
    out = []
    for p in sorted(Path(root).rglob("*.xml")):
        rel = p.relative_to(root).as_posix()
        if "vintf" in rel or p.name.startswith(("manifest", "compatibility_matrix")):
            r = parse_vintf_manifest(p, rel)
            if not r.get("ignored"):
                out.append(r)
    return out


def binder_interface_names(manifests: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Noms d'instance tels qu'enregistrés auprès du gestionnaire de services."""
    out = []
    for m in manifests:
        if m.get("kind") != "manifest":
            continue
        for h in m["hals"]:
            for inst in h["instances"]:
                if h["format"] == "aidl":
                    name = f"{h['name']}.{inst}"
                elif inst.startswith("@"):
                    ver, rest = inst.split("::", 1) if "::" in inst else (inst, "")
                    name = f"{h['name']}{ver}::{rest}"
                else:
                    name = f"{h['name']}::{inst}"
                out.append({"name": name, "format": h["format"], "hal": h["name"], "file": m["file"]})
    return out


def parse_permissions_xml(path: Path, rel: str) -> Dict[str, Any]:
    res: Dict[str, Any] = {"file": rel, "permissions": [], "features": [], "privapp": [], "assign": [],
                           "libraries": []}
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        res["error"] = str(e)
        return res
    if root.tag not in ("permissions", "config"):
        res["ignored"] = True
        return res
    for e in root:
        if e.tag == "permission":
            res["permissions"].append({"name": e.get("name"), "gids": [g.get("gid") for g in e.findall("group")]})
        elif e.tag == "feature":
            res["features"].append({"name": e.get("name"), "version": e.get("version")})
        elif e.tag == "unavailable-feature":
            res["features"].append({"name": e.get("name"), "unavailable": True})
        elif e.tag == "privapp-permissions":
            res["privapp"].append({"package": e.get("package"),
                                   "grant": [p.get("name") for p in e.findall("permission")],
                                   "deny": [p.get("name") for p in e.findall("deny-permission")]})
        elif e.tag == "assign-permission":
            res["assign"].append({"name": e.get("name"), "uid": e.get("uid")})
        elif e.tag == "library":
            res["libraries"].append({"name": e.get("name"), "file": e.get("file")})
    return res


def find_permissions(root: Path) -> Dict[str, Any]:
    files = []
    for p in sorted(Path(root).rglob("*.xml")):
        rel = p.relative_to(root).as_posix()
        if "/permissions/" in "/" + rel or "/sysconfig/" in "/" + rel:
            r = parse_permissions_xml(p, rel)
            if not r.get("ignored"):
                files.append(r)
    agg = {"files": [f["file"] for f in files],
           "gid_permissions": [p for f in files for p in f["permissions"]],
           "features": sorted({x["name"] for f in files for x in f["features"] if not x.get("unavailable")}),
           "unavailable_features": sorted({x["name"] for f in files for x in f["features"] if x.get("unavailable")}),
           "privapp": [p for f in files for p in f["privapp"]],
           "assign": [a for f in files for a in f["assign"]],
           "shared_libraries": [x for f in files for x in f["libraries"]]}
    return agg
