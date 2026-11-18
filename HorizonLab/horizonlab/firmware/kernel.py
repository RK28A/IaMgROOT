"""Identification du noyau Linux : chaîne de version, configuration embarquée (IKCONFIG)."""
from __future__ import annotations

import re
import zlib
from pathlib import Path
from typing import Any, Dict, Optional

from horizonlab.firmware.formats import decompress_any

LINUX_VERSION_RE = re.compile(rb"Linux version (\d+\.\d+[\w.\-+]*) \(([^)]{0,200})\)[^\n\0]{0,400}")

# Options de configuration intéressantes pour une lecture défensive.
SECURITY_CONFIGS = [
    "CONFIG_SECURITY_SELINUX", "CONFIG_SECURITY_SELINUX_DEVELOP", "CONFIG_SECCOMP",
    "CONFIG_SECCOMP_FILTER", "CONFIG_STACKPROTECTOR_STRONG", "CONFIG_CFI_CLANG", "CONFIG_SHADOW_CALL_STACK",
    "CONFIG_ARM64_PTR_AUTH", "CONFIG_ARM64_BTI_KERNEL", "CONFIG_ARM64_MTE", "CONFIG_KASAN",
    "CONFIG_HARDENED_USERCOPY", "CONFIG_INIT_STACK_ALL_ZERO", "CONFIG_RANDOMIZE_BASE",
    "CONFIG_STRICT_KERNEL_RWX", "CONFIG_DEBUG_FS", "CONFIG_KALLSYMS", "CONFIG_MODULES",
    "CONFIG_MODULE_SIG", "CONFIG_MODULE_SIG_FORCE", "CONFIG_DM_VERITY", "CONFIG_DM_VERITY_FEC",
    "CONFIG_ANDROID_BINDER_IPC", "CONFIG_ANDROID_BINDERFS", "CONFIG_IO_URING", "CONFIG_BPF_SYSCALL",
    "CONFIG_USERFAULTFD", "CONFIG_USER_NS", "CONFIG_QCOM_KGSL", "CONFIG_BT", "CONFIG_CFG80211",
    "CONFIG_DEVMEM", "CONFIG_PROC_KCORE", "CONFIG_IKCONFIG_PROC", "CONFIG_GKI_HACKS_TO_FIX",
    "CONFIG_LTO_CLANG", "CONFIG_KFENCE", "CONFIG_STATIC_USERMODEHELPER",
]


def find_kernel_blob(data: bytes) -> Dict[str, Any]:
    """Décompresse si besoin (gzip, LZ4 legacy, xz) en cherchant une signature connue."""
    method = "raw"
    if data[:2] == b"\x1f\x8b" or data[:4] in (b"\x02\x21\x4c\x18", b"\x04\x22\x4d\x18") or data[:6] == b"\xfd7zXZ\x00":
        data, method = decompress_any(data)
    elif b"Linux version " not in data:
        # Image.gz-dtb ou noyau précédé d'un en-tête : chercher un flux gzip interne.
        idx = data.find(b"\x1f\x8b\x08\x00")
        if idx >= 0:
            try:
                d = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data[idx:])
                data, method = d, f"gzip@{idx}"
            except zlib.error:
                pass
    return {"data": data, "method": method}


def kernel_info(data: bytes) -> Dict[str, Any]:
    blob = find_kernel_blob(data)
    k = blob["data"]
    info: Dict[str, Any] = {"decompression": blob["method"], "size": len(k)}
    m = LINUX_VERSION_RE.search(k)
    if m:
        info["version"] = m.group(1).decode("utf-8", "replace")
        info["banner"] = m.group(0).decode("utf-8", "replace").strip()
        info["compiler"] = m.group(2).decode("utf-8", "replace")
    if len(k) >= 0x40 and k[0x38:0x3C] == b"ARM\x64":
        import struct

        text_offset, image_size, flags = struct.unpack_from("<QQQ", k, 8)
        info["arm64_header"] = {"text_offset": hex(text_offset), "image_size": image_size,
                                "endianness": "BE" if flags & 1 else "LE",
                                "page_size_flag": (flags >> 1) & 3}
    cfg = extract_ikconfig(k)
    if cfg is not None:
        info["ikconfig_present"] = True
        opts = parse_kconfig(cfg)
        info["config_option_count"] = len(opts)
        info["security_config"] = {c: opts.get(c, "not set") for c in SECURITY_CONFIGS}
        info["_config_text"] = cfg
    else:
        info["ikconfig_present"] = False
    return info


def extract_ikconfig(k: bytes) -> Optional[str]:
    i = k.find(b"IKCFG_ST")
    if i < 0:
        return None
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        return d.decompress(k[i + 8:]).decode("utf-8", "replace")
    except zlib.error:
        return None


def parse_kconfig(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("CONFIG_") and "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            out[line[2:-11]] = "n"
    return out


def kernel_info_from_file(path: Path, offset: int = 0, size: Optional[int] = None) -> Dict[str, Any]:
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(size) if size else f.read()
    return kernel_info(data)


def modules_versions(root: Path) -> Dict[str, str]:
    """vermagic des modules .ko présents (vendor/lib/modules, vendor_dlkm...)."""
    out: Dict[str, str] = {}
    for ko in sorted(Path(root).rglob("*.ko"))[:2000]:
        try:
            data = ko.read_bytes()
        except OSError:
            continue
        m = re.search(rb"vermagic=([^\0]+)", data)
        if m:
            out[ko.relative_to(root).as_posix()] = m.group(1).decode("utf-8", "replace")
    return out
