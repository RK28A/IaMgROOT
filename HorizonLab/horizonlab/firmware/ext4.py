"""Lecteur ext4 en lecture seule, en Python pur (fonctionne sous Windows, sans montage).

Couvre ce qu'utilisent les images Android : extents (toute profondeur), adressage
par blocs classique (direct / indirect), répertoires linéaires et htree, données
« inline », liens symboliques, attributs étendus (``security.selinux`` notamment,
dans l'inode ou dans un bloc externe).

Le fichier image est ouvert en ``rb`` ; l'extraction écrit uniquement dans le
répertoire de destination fourni (copie de travail).
"""
from __future__ import annotations

import os
import stat
import struct
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

EXT4_EXTENTS_FL = 0x80000
EXT4_INLINE_DATA_FL = 0x10000000
XATTR_PREFIX = {1: "user.", 2: "system.posix_acl_access", 3: "system.posix_acl_default",
                4: "trusted.", 6: "security.", 7: "system.", 8: "system.richacl"}


class Ext4Error(Exception):
    pass


class Inode:
    __slots__ = ("num", "mode", "uid", "gid", "size", "flags", "block", "raw", "links", "file_acl")

    def __init__(self, num: int, raw: bytes):
        self.num = num
        self.raw = raw
        self.mode = struct.unpack_from("<H", raw, 0)[0]
        uid_lo, size_lo = struct.unpack_from("<HI", raw, 2)
        gid_lo, self.links = struct.unpack_from("<HH", raw, 0x18)
        self.flags = struct.unpack_from("<I", raw, 0x20)[0]
        self.block = raw[0x28:0x28 + 60]
        file_acl_lo = struct.unpack_from("<I", raw, 0x68)[0]
        size_hi = struct.unpack_from("<I", raw, 0x6C)[0]
        file_acl_hi, uid_hi, gid_hi = struct.unpack_from("<HHH", raw, 0x76)
        self.size = size_lo | (size_hi << 32)
        self.uid = uid_lo | (uid_hi << 16)
        self.gid = gid_lo | (gid_hi << 16)
        self.file_acl = file_acl_lo | (file_acl_hi << 32)

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.mode)

    @property
    def is_reg(self) -> bool:
        return stat.S_ISREG(self.mode)

    @property
    def is_link(self) -> bool:
        return stat.S_ISLNK(self.mode)


class Ext4Reader:
    def __init__(self, path: Path, offset: int = 0):
        self.path = Path(path)
        self.offset = offset
        self.f = open(self.path, "rb")
        sb = self._pread(1024, 1024)
        if struct.unpack_from("<H", sb, 56)[0] != 0xEF53:
            raise Ext4Error("superbloc ext4 introuvable")
        self.block_size = 1024 << struct.unpack_from("<I", sb, 24)[0]
        self.first_data_block = struct.unpack_from("<I", sb, 20)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 40)[0]
        self.blocks_per_group = struct.unpack_from("<I", sb, 32)[0]
        rev = struct.unpack_from("<I", sb, 76)[0]
        self.inode_size = struct.unpack_from("<H", sb, 88)[0] if rev >= 1 else 128
        self.incompat = struct.unpack_from("<I", sb, 96)[0]
        is64 = bool(self.incompat & 0x80)
        self.desc_size = struct.unpack_from("<H", sb, 0xFE)[0] if is64 else 32
        if self.desc_size < 32:
            self.desc_size = 32
        blocks = struct.unpack_from("<I", sb, 4)[0] | ((struct.unpack_from("<I", sb, 0x150)[0] << 32) if is64 else 0)
        ngroups = (blocks - self.first_data_block + self.blocks_per_group - 1) // self.blocks_per_group
        gdt = self._pread((self.first_data_block + 1) * self.block_size, ngroups * self.desc_size)
        self.inode_tables: List[int] = []
        for g in range(ngroups):
            d = gdt[g * self.desc_size:(g + 1) * self.desc_size]
            lo = struct.unpack_from("<I", d, 8)[0]
            hi = struct.unpack_from("<I", d, 0x28)[0] if is64 and self.desc_size >= 64 else 0
            self.inode_tables.append(lo | (hi << 32))

    # ----------------------------------------------------------------- bas niveau
    def close(self) -> None:
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def _pread(self, off: int, n: int) -> bytes:
        self.f.seek(self.offset + off)
        return self.f.read(n)

    def _block(self, b: int, count: int = 1) -> bytes:
        return self._pread(b * self.block_size, count * self.block_size)

    def inode(self, num: int) -> Inode:
        g, idx = divmod(num - 1, self.inodes_per_group)
        if g >= len(self.inode_tables):
            raise Ext4Error(f"inode {num} hors limites")
        raw = self._pread(self.inode_tables[g] * self.block_size + idx * self.inode_size, self.inode_size)
        return Inode(num, raw)

    def _extent_runs(self, data: bytes) -> Iterator[Tuple[int, int, int, bool]]:
        """(bloc_logique, bloc_physique, longueur, non_initialisé)"""
        magic, entries, _max, depth = struct.unpack_from("<HHHH", data, 0)
        if magic != 0xF30A:
            raise Ext4Error("en-tête d'extent invalide")
        for i in range(entries):
            e = data[12 + i * 12: 24 + i * 12]
            if depth == 0:
                lblk, ln, hi, lo = struct.unpack_from("<IHHI", e, 0)
                uninit = ln > 32768
                if uninit:
                    ln -= 32768
                yield lblk, lo | (hi << 32), ln, uninit
            else:
                _lblk, lo, hi = struct.unpack_from("<IIH", e, 0)
                yield from self._extent_runs(self._block(lo | (hi << 32)))

    def _blockmap_runs(self, ino: Inode) -> Iterator[Tuple[int, int, int, bool]]:
        ptrs = struct.unpack_from("<15I", ino.block, 0)
        per = self.block_size // 4
        lblk = 0
        nblocks = (ino.size + self.block_size - 1) // self.block_size

        def walk(b: int, level: int):
            nonlocal lblk
            if lblk >= nblocks:
                return
            if b == 0:
                lblk += per ** level if level else 1
                return
            if level == 0:
                yield lblk, b, 1, False
                lblk += 1
                return
            for p in struct.unpack_from(f"<{per}I", self._block(b), 0):
                yield from walk(p, level - 1)

        for i in range(12):
            yield from walk(ptrs[i], 0)
        for lvl, i in ((1, 12), (2, 13), (3, 14)):
            yield from walk(ptrs[i], lvl)

    def read(self, ino: Inode, limit: Optional[int] = None) -> bytes:
        size = ino.size if limit is None else min(ino.size, limit)
        if ino.flags & EXT4_INLINE_DATA_FL:
            data = ino.block
            extra = self.xattrs(ino).get("system.data", b"")
            return (data + extra)[:size]
        if ino.is_link and ino.size < 60 and not ino.flags & EXT4_EXTENTS_FL:
            blocks_lo = struct.unpack_from("<I", ino.raw, 0x1C)[0]
            if blocks_lo == 0 or ino.file_acl and blocks_lo == self.block_size // 512:
                return ino.block[:ino.size]
        buf = bytearray(size)
        runs = self._extent_runs(ino.block) if ino.flags & EXT4_EXTENTS_FL else self._blockmap_runs(ino)
        for lblk, pblk, ln, uninit in runs:
            start = lblk * self.block_size
            if start >= size or uninit:
                continue
            n = min(ln * self.block_size, size - start)
            buf[start:start + n] = self._pread(pblk * self.block_size, n)
        return bytes(buf)

    def xattrs(self, ino: Inode) -> Dict[str, bytes]:
        out: Dict[str, bytes] = {}
        if self.inode_size > 128:
            extra = struct.unpack_from("<H", ino.raw, 0x80)[0]
            base = 0x80 + extra
            if base + 4 <= len(ino.raw) and struct.unpack_from("<I", ino.raw, base)[0] == 0xEA020000:
                region = ino.raw[base + 4:]
                self._parse_xattr_entries(region, region, out)
        if ino.file_acl:
            blk = self._block(ino.file_acl)
            if struct.unpack_from("<I", blk, 0)[0] == 0xEA020000:
                self._parse_xattr_entries(blk[32:], blk, out)
        return out

    @staticmethod
    def _parse_xattr_entries(entries: bytes, value_base: bytes, out: Dict[str, bytes]) -> None:
        o = 0
        while o + 16 <= len(entries):
            name_len, name_idx, voff, vinum, vsize = struct.unpack_from("<BBHII", entries, o)
            if name_len == 0 and name_idx == 0 and voff == 0:
                break
            name = entries[o + 16:o + 16 + name_len].decode("utf-8", "replace")
            if vinum == 0:
                out[XATTR_PREFIX.get(name_idx, f"idx{name_idx}.") + name] = value_base[voff:voff + vsize]
            o += (16 + name_len + 3) & ~3

    # ----------------------------------------------------------------- répertoires
    def listdir(self, ino: Inode) -> List[Tuple[str, int, int]]:
        if not ino.is_dir:
            raise Ext4Error("pas un répertoire")
        data = self.read(ino)
        out: List[Tuple[str, int, int]] = []
        o = 0
        if ino.flags & EXT4_INLINE_DATA_FL:
            parent = struct.unpack_from("<I", data, 0)[0]
            out.append(("..", parent, 2))
            o = 4
        while o + 8 <= len(data):
            inum, rec_len, name_len, ftype = struct.unpack_from("<IHBB", data, o)
            if rec_len < 8:
                break
            if inum and name_len:
                name = data[o + 8:o + 8 + name_len].decode("utf-8", "surrogateescape")
                out.append((name, inum, ftype))
            o += rec_len
        return out

    def lookup(self, path: str) -> Inode:
        ino = self.inode(2)
        for part in [p for p in path.strip("/").split("/") if p]:
            for name, inum, _t in self.listdir(ino):
                if name == part:
                    ino = self.inode(inum)
                    break
            else:
                raise FileNotFoundError(path)
        return ino

    def walk(self) -> Iterator[Tuple[str, Inode]]:
        """Parcours en profondeur ; produit (chemin, inode) pour chaque entrée sauf la racine."""
        stack = [("", self.inode(2))]
        seen = {2}
        while stack:
            prefix, d = stack.pop()
            for name, inum, _t in sorted(self.listdir(d)):
                if name in (".", "..") or (name == "lost+found" and prefix == ""):
                    continue
                child = self.inode(inum)
                path = f"{prefix}/{name}"
                yield path, child
                if child.is_dir and inum not in seen:
                    seen.add(inum)
                    stack.append((path, child))

    # ----------------------------------------------------------------- extraction
    def extract_all(self, dest: Path, max_file_size: Optional[int] = None) -> List[Dict]:
        """Extrait l'arborescence dans ``dest`` ; renvoie les métadonnées de chaque entrée.

        Les liens symboliques ne sont pas créés (portabilité Windows) : leur cible est
        enregistrée dans les métadonnées et dans ``.horizonlab_symlinks.tsv``.
        """
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        meta: List[Dict] = []
        links = []
        for path, ino in self.walk():
            x = self.xattrs(ino)
            label = x.get("security.selinux", b"").rstrip(b"\0").decode("utf-8", "replace") or None
            caps = x.get("security.capability")
            entry = {"path": path, "mode": oct(ino.mode & 0o7777), "uid": ino.uid, "gid": ino.gid,
                     "size": ino.size, "selinux": label, "has_capabilities": caps is not None}
            target = dest / path.lstrip("/")
            if ino.is_dir:
                entry["type"] = "dir"
                target.mkdir(parents=True, exist_ok=True)
            elif ino.is_link:
                entry["type"] = "symlink"
                entry["target"] = self.read(ino).decode("utf-8", "surrogateescape")
                links.append((path, entry["target"]))
            elif ino.is_reg:
                entry["type"] = "file"
                target.parent.mkdir(parents=True, exist_ok=True)
                if max_file_size is not None and ino.size > max_file_size:
                    entry["skipped"] = "trop volumineux"
                else:
                    target.write_bytes(self.read(ino))
            else:
                entry["type"] = "special"
            meta.append(entry)
        if links:
            (dest / ".horizonlab_symlinks.tsv").write_text(
                "".join(f"{p}\t{t}\n" for p, t in links), encoding="utf-8")
        return meta


def safe_join(root: Path, rel: str) -> Path:
    """Jointure qui empêche toute sortie de ``root`` (« ../ » malveillants)."""
    p = (Path(root) / rel.lstrip("/")).resolve()
    if os.path.commonpath([str(p), str(Path(root).resolve())]) != str(Path(root).resolve()):
        raise ValueError(f"chemin hors racine : {rel}")
    return p
