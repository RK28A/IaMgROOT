"""Décodeur de XML binaire Android (AndroidManifest.xml compilé) et résumé de manifeste."""
from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_RESOURCE_MAP = 0x0180

# Identifiants de ressources android:* (utiles si les noms d'attributs sont effacés).
ANDROID_ATTR_IDS = {
    0x01010003: "name", 0x01010006: "permission", 0x01010009: "protectionLevel",
    0x0101000B: "sharedUserId", 0x0101000F: "debuggable", 0x01010010: "exported",
    0x01010011: "process", 0x0101021B: "versionCode", 0x0101021C: "versionName",
    0x0101020C: "minSdkVersion", 0x01010270: "targetSdkVersion", 0x01010001: "label",
    0x01010018: "authorities", 0x0101001A: "grantUriPermissions", 0x01010280: "allowBackup",
    0x0101000D: "persistent",
}
PROTECTION_LEVELS = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem", 4: "internal"}
PROTECTION_FLAGS = {0x10: "privileged", 0x20: "development", 0x40: "appop", 0x80: "pre23",
                    0x100: "installer", 0x200: "verifier", 0x400: "preinstalled", 0x800: "setup",
                    0x1000: "instant", 0x2000: "runtime", 0x4000: "oem", 0x8000: "vendorPrivileged",
                    0x10000: "textClassifier", 0x100000: "role", 0x40000: "configurator"}


class AxmlError(Exception):
    pass


def _string_pool(buf: bytes, off: int) -> List[str]:
    _t, hsize, _size = struct.unpack_from("<HHI", buf, off)
    count, _styles, flags, strings_start, _ = struct.unpack_from("<IIIII", buf, off + 8)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", buf, off + hsize)
    base = off + strings_start
    out = []
    for so in offsets:
        p = base + so
        if utf8:
            n = buf[p]
            p += 2 if n & 0x80 else 1
            n = buf[p]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | buf[p + 1]
                p += 2
            else:
                p += 1
            out.append(buf[p:p + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", buf, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, p)[0]
                p += 2
            out.append(buf[p:p + n * 2].decode("utf-16-le", "replace"))
    return out


def parse_axml(buf: bytes) -> List[Tuple[int, str, Dict[str, Any]]]:
    """Renvoie la liste (profondeur, balise, attributs) dans l'ordre du document."""
    if len(buf) < 8 or struct.unpack_from("<H", buf, 0)[0] != RES_XML:
        raise AxmlError("pas un XML binaire Android")
    strings: List[str] = []
    resmap: List[int] = []
    out: List[Tuple[int, str, Dict[str, Any]]] = []
    depth = 0
    o = struct.unpack_from("<H", buf, 2)[0]
    while o + 8 <= len(buf):
        ctype, hsize, csize = struct.unpack_from("<HHI", buf, o)
        if csize < 8:
            break
        if ctype == RES_STRING_POOL:
            strings = _string_pool(buf, o)
        elif ctype == RES_XML_RESOURCE_MAP:
            resmap = list(struct.unpack_from(f"<{(csize - hsize) // 4}I", buf, o + hsize))
        elif ctype == RES_XML_START_ELEMENT:
            ext = o + hsize
            _ns, name_i, astart, asize, acount = struct.unpack_from("<IIHHH", buf, ext)
            tag = strings[name_i] if name_i < len(strings) else "?"
            attrs: Dict[str, Any] = {}
            for i in range(acount):
                a = ext + astart + i * asize
                _ans, an, raw, _sz, _r0, dtype, data = struct.unpack_from("<IIIHBBI", buf, a)
                aname = strings[an] if an < len(strings) else ""
                if (not aname) and an < len(resmap):
                    aname = ANDROID_ATTR_IDS.get(resmap[an], f"0x{resmap[an]:08x}")
                if dtype == 0x03:
                    val: Any = strings[data] if data < len(strings) else raw
                elif dtype == 0x12:
                    val = data != 0
                elif dtype in (0x10, 0x11):
                    val = data
                elif dtype == 0x01:
                    val = f"@0x{data:08x}"
                else:
                    val = strings[raw] if raw != 0xFFFFFFFF and raw < len(strings) else data
                attrs[aname] = val
            out.append((depth, tag, attrs))
            depth += 1
        elif ctype == RES_XML_END_ELEMENT:
            depth -= 1
        o += csize
    return out


def protection_level(v: Any) -> str:
    if isinstance(v, str):
        return v
    base = PROTECTION_LEVELS.get(v & 0xF, str(v & 0xF))
    flags = [n for b, n in PROTECTION_FLAGS.items() if v & b]
    return "|".join([base] + flags)


def summarize_manifest(nodes: List[Tuple[int, str, Dict[str, Any]]]) -> Dict[str, Any]:
    res: Dict[str, Any] = {"package": None, "uses_permissions": [], "permissions": [], "services": [],
                           "receivers": [], "providers": [], "activities": 0}
    for _d, tag, a in nodes:
        if tag == "manifest":
            res["package"] = a.get("package")
            res["version_code"] = a.get("versionCode")
            res["version_name"] = a.get("versionName")
            res["shared_user_id"] = a.get("sharedUserId")
        elif tag == "uses-sdk":
            res["min_sdk"] = a.get("minSdkVersion")
            res["target_sdk"] = a.get("targetSdkVersion")
        elif tag in ("uses-permission", "uses-permission-sdk-23"):
            if a.get("name"):
                res["uses_permissions"].append(a["name"])
        elif tag == "permission":
            res["permissions"].append({"name": a.get("name"),
                                       "protection_level": protection_level(a.get("protectionLevel", 0))})
        elif tag == "application":
            res["debuggable"] = a.get("debuggable", False)
            res["persistent"] = a.get("persistent", False)
            res["process"] = a.get("process")
        elif tag in ("service", "receiver", "provider"):
            item = {"name": a.get("name"), "exported": a.get("exported"), "permission": a.get("permission"),
                    "process": a.get("process")}
            if tag == "provider":
                item["authorities"] = a.get("authorities")
            res[tag + "s"].append(item)
        elif tag == "activity":
            res["activities"] += 1
    return res


def read_apk_manifest(apk: Path) -> Dict[str, Any]:
    with zipfile.ZipFile(apk) as z:
        try:
            data = z.read("AndroidManifest.xml")
        except KeyError:
            return {"error": "AndroidManifest.xml absent"}
        info = summarize_manifest(parse_axml(data))
        names = z.namelist()
        info["has_dex"] = any(n.endswith(".dex") for n in names)
        info["native_abis"] = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2})
        return info


def read_apex_manifest(apex: Path) -> Dict[str, Any]:
    """APEX : apex_manifest.pb (protobuf : 1=name, 2=version) + AndroidManifest.xml."""
    from horizonlab.firmware.formats import pb_decode

    out: Dict[str, Any] = {}
    with zipfile.ZipFile(apex) as z:
        names = z.namelist()
        if "apex_manifest.pb" in names:
            m = pb_decode(z.read("apex_manifest.pb"))
            out["name"] = m.get(1, [b""])[0].decode("utf-8", "replace")
            out["version"] = m.get(2, [None])[0]
            out["provide_native_libs"] = [x.decode() for x in m.get(4, [])]
            out["require_native_libs"] = [x.decode() for x in m.get(5, [])]
        elif "apex_manifest.json" in names:
            import json

            out.update(json.loads(z.read("apex_manifest.json")))
        out["payload"] = next((n for n in names if n.startswith("apex_payload")), None)
        out["has_pubkey"] = "apex_pubkey" in names
    return out
