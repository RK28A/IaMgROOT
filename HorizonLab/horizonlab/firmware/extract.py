"""Préparation d'une arborescence analysable à partir d'images ou d'un répertoire extrait.

Toutes les sorties vont dans l'espace de travail ; les entrées sont lues en ``rb``.
"""
from __future__ import annotations

import logging
import re
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from horizonlab.core.tools import run, which
from horizonlab.core.workspace import Workspace
from horizonlab.firmware import formats
from horizonlab.firmware.ext4 import Ext4Reader
from horizonlab.firmware.kernel import kernel_info

log = logging.getLogger("horizonlab.firmware.extract")

FS_PARTITIONS = {"system", "vendor", "product", "system_ext", "odm", "vendor_dlkm", "odm_dlkm",
                 "system_dlkm", "oem", "persist", "userdata_ro"}
SLOT_RE = re.compile(r"_(a|b)$")
IMAGE_EXTS = {".img", ".bin", ".ext4", ".erofs", ".raw", ".mbn", ".elf", ".zip"}


def partition_name(p: Path) -> str:
    name = p.name
    for ext in (".img", ".ext4", ".erofs", ".raw", ".bin"):
        if name.lower().endswith(ext):
            name = name[: -len(ext)]
            break
    return SLOT_RE.sub("", name)


def looks_extracted(d: Path) -> bool:
    """Un répertoire déjà extrait contient system/, vendor/ ou un build.prop."""
    return any((d / x).is_dir() for x in ("system", "vendor", "product")) or (d / "build.prop").exists()


class Preparer:
    def __init__(self, ws: Workspace, extract_filesystems: bool = True, max_file_size: Optional[int] = None):
        self.ws = ws
        self.extract_filesystems = extract_filesystems
        self.max_file_size = max_file_size
        self.partitions: List[Dict[str, Any]] = []
        self.kernels: List[Dict[str, Any]] = []
        self.avb: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.rootfs = ws.work / "rootfs"

    # ------------------------------------------------------------------ entrée
    def prepare(self, src: Path) -> Dict[str, Any]:
        src = Path(src)
        if src.is_dir():
            if looks_extracted(src):
                root = src
                mode = "extracted_tree"
                # Les images éventuellement présentes à côté sont aussi inventoriées.
                for img in sorted(p for p in src.iterdir() if p.is_file() and p.suffix.lower() in IMAGE_EXTS):
                    self.process_image(img, extract=False)
            else:
                mode = "image_directory"
                imgs = sorted(p for p in src.rglob("*") if p.is_file() and
                              (p.suffix.lower() in IMAGE_EXTS or p.name == "payload.bin"))
                for img in imgs:
                    self.process_image(img)
                root = self.rootfs
                if not self.rootfs.exists():
                    # Aucune image extractible : un sous-répertoire déjà extrait peut servir de racine.
                    for sub in sorted(p for p in src.iterdir() if p.is_dir()):
                        if looks_extracted(sub):
                            self.warnings.append(f"racine prise dans le sous-répertoire extrait {sub.name}")
                            root = sub
                            break
        else:
            mode = "single_image"
            self.process_image(src)
            root = self.rootfs
        return {"mode": mode, "root": root, "partitions": self.partitions, "kernels": self.kernels,
                "avb": self.avb, "warnings": self.warnings}

    # ------------------------------------------------------------------ images
    def process_image(self, img: Path, extract: bool = True, name: Optional[str] = None,
                      origin: Optional[str] = None) -> Dict[str, Any]:
        fmt = formats.detect_format(img)
        name = name or partition_name(img)
        entry: Dict[str, Any] = {"name": name, "file": img.name, "format": fmt, "size": img.stat().st_size,
                                 "origin": origin or "input"}
        self.partitions.append(entry)
        try:
            if fmt == "sparse":
                entry["sparse"] = formats.parse_sparse_header(img)
                raw = self.ws.path("unsparsed", f"{name}.raw.img")
                formats.unsparse(img, raw)
                self.partitions.pop()
                sub = self.process_image(raw, extract, name, origin=f"unsparse({img.name})")
                sub["sparse"] = entry["sparse"]
                sub["file"] = img.name
                return sub
            if fmt == "ext4":
                with open(img, "rb") as f:
                    entry["filesystem"] = formats.parse_ext4_superblock(f)
                if extract and self.extract_filesystems:
                    dest = self.rootfs / name
                    self.ws.guard.check_writable(dest)
                    with Ext4Reader(img) as r:
                        meta = r.extract_all(dest, self.max_file_size)
                    entry["extracted_to"] = dest.relative_to(self.ws.root).as_posix()
                    entry["entries"] = len(meta)
                    entry["selinux_labeled"] = sum(1 for m in meta if m.get("selinux"))
                    self._save_fs_meta(name, meta)
            elif fmt == "erofs":
                with open(img, "rb") as f:
                    entry["filesystem"] = formats.parse_erofs_superblock(f)
                if extract and self.extract_filesystems:
                    tool = which("fsck.erofs")
                    dest = self.rootfs / name
                    self.ws.guard.check_writable(dest)
                    if tool:
                        dest.mkdir(parents=True, exist_ok=True)
                        r = run([tool, f"--extract={dest}", "--no-preserve", str(img)], timeout=1800)
                        if not r.ok:
                            r = run([tool, f"--extract={dest}", str(img)], timeout=1800)
                        entry["extracted_to"] = dest.relative_to(self.ws.root).as_posix()
                        entry["extract_tool"] = "fsck.erofs"
                        if not r.ok:
                            self.warnings.append(f"fsck.erofs a échoué sur {img.name} : {r.stderr[-300:]}")
                    else:
                        self.warnings.append(f"{img.name} : EROFS non extrait (installez erofs-utils / fsck.erofs)")
            elif fmt == "super":
                meta = formats.parse_super(img)
                entry["super"] = {k: v for k, v in meta.items() if k != "partitions"}
                entry["logical_partitions"] = [{"name": p["name"], "size": p["size"], "group": p["group"],
                                                "attributes": p["attributes"]} for p in meta["partitions"]]
                if extract:
                    for p in meta["partitions"]:
                        if p["size"] == 0:
                            continue
                        out = self.ws.path("super", f"{p['name']}.img")
                        formats.extract_super_partition(img, p, out)
                        self.process_image(out, extract, partition_name(Path(p["name"] + ".img")),
                                           origin=f"super({img.name})")
            elif fmt in ("boot", "vendor_boot"):
                self._process_boot(img, fmt, entry, extract)
            elif fmt == "vbmeta" or fmt == "avb_footer_image":
                v = formats.parse_vbmeta(img)
                v["partition"] = name
                self.avb.append(v)
                entry["avb"] = {k: v[k] for k in ("algorithm", "rollback_index", "flags_decoded", "release_string")}
            elif fmt == "dtbo":
                entry["dtbo"] = formats.parse_dtbo(img)
            elif fmt == "payload":
                p = formats.parse_payload(img)
                entry["payload"] = p
                if extract and p["full_ota"]:
                    for part in p["partitions"]:
                        out = self.ws.path("payload", f"{part['name']}.img")
                        res = formats.extract_payload_partition(img, part["name"], out)
                        if res["unsupported_operations"]:
                            self.warnings.append(f"payload {part['name']} : opérations non gérées {res['unsupported_operations']}")
                            continue
                        self.process_image(out, extract, part["name"], origin=f"payload({img.name})")
            elif fmt == "zip":
                with zipfile.ZipFile(img) as z:
                    names = z.namelist()
                    entry["zip_entries"] = len(names)
                    if "payload.bin" in names and extract:
                        out = self.ws.path("ota", "payload.bin")
                        with z.open("payload.bin") as s, open(out, "wb") as d:
                            shutil.copyfileobj(s, d)
                        self.process_image(out, extract, "payload", origin=f"zip({img.name})")
            elif fmt == "arm64_kernel" or (fmt in ("gzip", "lz4") and "kernel" in name.lower()):
                ki = kernel_info(img.read_bytes())
                self._add_kernel(ki, name)
            # Pied de page AVB éventuel sur une image de partition
            if fmt not in ("vbmeta", "avb_footer_image") and entry["size"] >= 64:
                with open(img, "rb") as f:
                    foot = formats.parse_avb_footer(f, entry["size"])
                if foot:
                    try:
                        v = formats.parse_vbmeta(img)
                        v["partition"] = name
                        self.avb.append(v)
                        entry["avb_footer"] = foot
                    except (ValueError, IndexError) as e:
                        self.warnings.append(f"{img.name} : pied AVB illisible ({e})")
        except Exception as e:  # noqa: BLE001 - une image défectueuse ne doit pas arrêter l'analyse
            entry["error"] = f"{type(e).__name__}: {e}"
            self.warnings.append(f"{img.name} : {entry['error']}")
            log.exception("échec sur %s", img)
        return entry

    def _process_boot(self, img: Path, fmt: str, entry: Dict[str, Any], extract: bool) -> None:
        info = formats.parse_boot_image(img) if fmt == "boot" else formats.parse_vendor_boot(img)
        entry["boot"] = info
        with open(img, "rb") as f:
            if fmt == "boot" and info.get("kernel_size"):
                f.seek(info["kernel_offset"])
                kdata = f.read(info["kernel_size"])
                ki = kernel_info(kdata)
                self._add_kernel(ki, entry["name"])
                entry["kernel_version"] = ki.get("version")
            rd_size = info.get("ramdisk_size") or info.get("vendor_ramdisk_size")
            if rd_size and extract:
                f.seek(info["ramdisk_offset"])
                rd = f.read(rd_size)
                try:
                    data, method = formats.decompress_any(rd)
                    dest = self.rootfs / f"{entry['name']}_ramdisk"
                    self.ws.guard.check_writable(dest)
                    count = 0
                    for nm, mode, content in formats.iter_cpio(data):
                        if nm.startswith("/") or ".." in Path(nm).parts:
                            continue
                        t = dest / nm
                        if (mode & 0o170000) == 0o040000:
                            t.mkdir(parents=True, exist_ok=True)
                        elif (mode & 0o170000) == 0o100000:
                            t.parent.mkdir(parents=True, exist_ok=True)
                            t.write_bytes(content)
                        count += 1
                    entry["ramdisk"] = {"compression": method, "entries": count,
                                        "extracted_to": dest.relative_to(self.ws.root).as_posix()}
                except Exception as e:  # noqa: BLE001
                    entry["ramdisk"] = {"error": str(e)}

    def _add_kernel(self, ki: Dict[str, Any], source: str) -> None:
        cfg = ki.pop("_config_text", None)
        ki["source"] = source
        if cfg:
            p = self.ws.path("kernel", f"{source}.config")
            p.write_text(cfg, encoding="utf-8")
            ki["config_file"] = p.relative_to(self.ws.root).as_posix()
        self.kernels.append(ki)

    def _save_fs_meta(self, name: str, meta: List[Dict]) -> None:
        import json

        p = self.ws.path("fsmeta", f"{name}.json")
        p.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")


def find_kernel_files(root: Path) -> List[Path]:
    cands: List[Path] = []
    seen = set()
    for pat in ("kernel", "Image", "Image.gz", "Image.lz4", "*/kernel", "*/Image", "*/Image.gz", "vmlinux"):
        for p in sorted(Path(root).glob(pat)):
            rp = p.resolve()
            if p.is_file() and rp not in seen:
                seen.add(rp)
                cands.append(p)
    return cands
