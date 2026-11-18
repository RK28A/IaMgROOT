"""Construction d'un sysroot de laboratoire (copie de travail) à partir d'une arborescence extraite.

* Les fichiers sont COPIÉS (jamais liés en dur) : le laboratoire ne peut pas altérer l'original.
* Les liens symboliques absolus (ex. /system/bin/linker64 → /apex/...) sont réécrits en liens
  RELATIFS au sysroot, sinon le noyau hôte les résoudrait vers la racine de l'hôte.
* Les APEX (zip contenant apex_payload.img ext4/erofs) sont dépliés sous /apex/<nom>.
* Un « profil matériel » crée des fichiers factices (/sys, /proc, /dev/...) documentés comme tels.
"""
from __future__ import annotations

import json
import os
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from horizonlab.core.tools import run, which
from horizonlab.core.workspace import ReadOnlyGuard
from horizonlab.firmware.ext4 import Ext4Reader
from horizonlab.firmware.formats import detect_format
from horizonlab.firmware.inventory import read_symlink_table

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"
PARTS = ("system", "vendor", "product", "system_ext", "odm", "vendor_dlkm", "odm_dlkm", "system_dlkm")


def _copy_tree(src: Path, dst: Path) -> int:
    n = 0
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        rel = Path(dirpath).relative_to(src)
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for d in list(dirnames):
            if (Path(dirpath) / d).is_symlink():
                dirnames.remove(d)
                filenames.append(d)
        for fn in filenames:
            s = Path(dirpath) / fn
            t = dst / rel / fn
            if s.is_symlink():
                target = os.readlink(s)
                if t.is_symlink() or t.exists():
                    t.unlink()
                os.symlink(target, t)
            elif fn != ".horizonlab_symlinks.tsv":
                shutil.copy2(s, t)
                n += 1
    return n


class SysrootBuilder:
    def __init__(self, tree: Path, dest: Path, protected: Optional[List[Path]] = None):
        self.tree = Path(tree)
        self.dest = Path(dest)
        guard = ReadOnlyGuard([self.tree] + list(protected or []))
        guard.check_writable(self.dest)
        self.log: List[str] = []
        self.differences: List[str] = []

    def build(self, profile: Optional[str] = "default", clean: bool = True) -> Dict[str, Any]:
        if clean and self.dest.exists():
            shutil.rmtree(self.dest)
        self.dest.mkdir(parents=True, exist_ok=True)
        copied = {}
        for part in PARTS:
            src = self._partition_src(part)
            if src is None:
                continue
            copied[part] = _copy_tree(src, self.dest / part)
            self.log.append(f"{part}: {copied[part]} fichiers copiés depuis {src}")
        links = self._restore_symlinks()
        apex = self._unpack_apexes()
        for d in ("data/local/tmp", "dev", "tmp", "mnt", "cache", "linkerconfig"):
            (self.dest / d).mkdir(parents=True, exist_ok=True)
        hw = self.apply_hardware_profile(profile) if profile else []
        self.differences += [
            "Noyau : celui de l'hôte (QEMU mode utilisateur), pas le noyau du casque ; pas de Binder, KGSL, ni pilotes Qualcomm.",
            "SELinux : non appliqué dans le laboratoire (l'hôte n'applique pas la politique Android).",
            "init/property_service absents : les propriétés système ne sont pas servies (/dev/__properties__ vide).",
            "seccomp : les filtres Android (minijail) ne sont pas installés par le laboratoire.",
            "Fichiers matériels (/sys, /proc, /dev) éventuellement simulés par des fichiers statiques du profil.",
        ]
        manifest = {"tree": self.tree.as_posix(), "sysroot": self.dest.as_posix(), "copied": copied,
                    "symlinks_restored": links, "apex": apex, "hardware_stubs": hw, "log": self.log,
                    "differences_vs_device": self.differences}
        (self.dest / ".horizonlab_sysroot.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
        return manifest

    def _partition_src(self, part: str) -> Optional[Path]:
        if part == "system":
            for c in (self.tree / "system" / "system", self.tree / "system"):
                if (c / "build.prop").exists() or (c / "bin").is_dir():
                    return c
            return None
        for c in (self.tree / part, self.tree / "system" / part, self.tree / "system" / "system" / part):
            if c.is_dir() and any(c.iterdir()):
                return c
        return None

    def _restore_symlinks(self) -> int:
        table = read_symlink_table(self.tree)
        n = 0
        for rel, target in table.items():
            dev = "/" + rel.lstrip("/")
            if dev.startswith("/system/system/"):
                dev = dev[len("/system"):]
            link = self.dest / dev.lstrip("/")
            if not link.parent.is_dir():
                continue
            n += self._make_link(link, target)
        # liens absolus déjà présents (copiés tels quels) → relatifs
        for p in list(self.dest.rglob("*")):
            if p.is_symlink() and os.readlink(p).startswith("/"):
                n += self._make_link(p, os.readlink(p))
        return n

    def _make_link(self, link: Path, target: str) -> int:
        if target.startswith("/"):
            abs_target = self.dest / target.lstrip("/")
            target = os.path.relpath(abs_target, link.parent)
        try:
            if link.is_symlink() or link.exists():
                if link.is_dir() and not link.is_symlink():
                    return 0
                link.unlink()
            os.symlink(target, link)
            return 1
        except OSError as e:  # Windows sans privilège symlink
            self.log.append(f"lien non créé {link}: {e}")
            return 0

    def _unpack_apexes(self) -> List[Dict[str, Any]]:
        out = []
        for apex in sorted(self.dest.rglob("*.apex")):
            name = apex.stem.split("@")[0]
            target = self.dest / "apex" / name
            rec: Dict[str, Any] = {"apex": apex.relative_to(self.dest).as_posix(), "mounted_at": f"/apex/{name}"}
            try:
                with zipfile.ZipFile(apex) as z:
                    if "apex_payload.img" not in z.namelist():
                        rec["status"] = "pas de apex_payload.img (APEX compressé ?)"
                        out.append(rec)
                        continue
                    tmp = self.dest / ".apex_tmp" / f"{name}.img"
                    tmp.parent.mkdir(parents=True, exist_ok=True)
                    with z.open("apex_payload.img") as s, open(tmp, "wb") as d:
                        shutil.copyfileobj(s, d)
                fmt = detect_format(tmp)
                if fmt == "ext4":
                    with Ext4Reader(tmp) as r:
                        r.extract_all(target)
                    rec["status"] = "ok (ext4)"
                elif fmt == "erofs" and which("fsck.erofs"):
                    target.mkdir(parents=True, exist_ok=True)
                    res = run([which("fsck.erofs"), f"--extract={target}", str(tmp)], timeout=600)
                    rec["status"] = "ok (erofs)" if res.ok else f"échec fsck.erofs: {res.stderr[-200:]}"
                else:
                    rec["status"] = f"format {fmt} non extrait"
                tmp.unlink(missing_ok=True)
            except (zipfile.BadZipFile, OSError) as e:
                rec["status"] = f"erreur: {e}"
            out.append(rec)
        shutil.rmtree(self.dest / ".apex_tmp", ignore_errors=True)
        return out

    def apply_hardware_profile(self, profile: str) -> List[Dict[str, str]]:
        profiles = json.loads((CONFIG_DIR / "lab_profiles.json").read_text(encoding="utf-8"))
        prof = profiles["profiles"].get(profile)
        if prof is None:
            raise KeyError(f"profil matériel inconnu : {profile}")
        made = []
        for path, content in prof.get("files", {}).items():
            p = self.dest / path.lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            made.append({"path": path, "simulated": True})
        if made:
            self.differences.append(f"Profil matériel « {profile} » : {len(made)} fichiers factices "
                                    f"(valeurs statiques, aucun pilote ni ioctl).")
        return made
