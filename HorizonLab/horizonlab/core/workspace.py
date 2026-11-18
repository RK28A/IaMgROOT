"""Hachage, espace de travail et garde-fous en écriture.

Principe : les images / arborescences d'origine ne sont JAMAIS ouvertes en écriture.
Toute extraction ou transformation se fait dans ``Workspace.work`` (copies de travail).
``ReadOnlyGuard`` refuse toute destination située sous un chemin protégé et
``OriginalsSeal`` permet de prouver (par SHA-256 avant/après) que les originaux
n'ont pas été modifiés par une analyse.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Dict, Iterable, List, Optional

CHUNK = 1024 * 1024


class SafetyError(RuntimeError):
    """Levée quand une opération violerait une règle de sécurité du projet."""


def sha256_file(path: Path, chunk: int = CHUNK) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:  # lecture seule
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resolve(p: Path) -> Path:
    try:
        return Path(p).resolve()
    except OSError:
        return Path(os.path.abspath(p))


def is_within(child: Path, parent: Path) -> bool:
    c, p = _resolve(child), _resolve(parent)
    try:
        c.relative_to(p)
        return True
    except ValueError:
        return False


class ReadOnlyGuard:
    """Liste de chemins protégés ; ``check_writable`` lève ``SafetyError`` si besoin."""

    def __init__(self, protected: Iterable[Path] = ()):  # noqa: D401
        self.protected: List[Path] = [_resolve(Path(p)) for p in protected]

    def protect(self, path: Path) -> None:
        self.protected.append(_resolve(Path(path)))

    def check_writable(self, dest: Path) -> Path:
        d = _resolve(Path(dest))
        for p in self.protected:
            if d == p or is_within(d, p):
                raise SafetyError(f"écriture refusée : {d} est sous un chemin d'origine protégé ({p})")
        return d


class Workspace:
    """Répertoire de travail d'une analyse : ``work/`` (copies), ``out/`` (rapports)."""

    def __init__(self, root: Path, protected: Iterable[Path] = ()):
        self.root = _resolve(Path(root))
        self.guard = ReadOnlyGuard(protected)
        self.guard.check_writable(self.root)
        self.work = self.root / "work"
        self.out = self.root / "out"
        self.logs = self.root / "logs"
        for d in (self.work, self.out, self.logs):
            d.mkdir(parents=True, exist_ok=True)

    def path(self, *parts: str) -> Path:
        p = self.work.joinpath(*parts)
        self.guard.check_writable(p)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def copy_in(self, src: Path, rel: str) -> Path:
        """Copie un fichier d'origine dans l'espace de travail (copie de travail)."""
        dest = self.path(rel)
        shutil.copy2(src, dest)
        return dest


class OriginalsSeal:
    """Empreintes SHA-256 + taille + mtime des originaux, pour vérification avant/après."""

    def __init__(self, entries: Optional[Dict[str, Dict]] = None):
        self.entries: Dict[str, Dict] = entries or {}

    @classmethod
    def capture(cls, paths: Iterable[Path], hash_limit: Optional[int] = None) -> "OriginalsSeal":
        entries: Dict[str, Dict] = {}
        for p in paths:
            p = Path(p)
            files = [p] if p.is_file() else sorted(x for x in p.rglob("*") if x.is_file() and not x.is_symlink())
            for f in files:
                st = f.stat()
                e = {"size": st.st_size, "mtime_ns": st.st_mtime_ns}
                if hash_limit is None or st.st_size <= hash_limit:
                    e["sha256"] = sha256_file(f)
                entries[_resolve(f).as_posix()] = e
        return cls(entries)

    def verify(self) -> List[str]:
        """Retourne la liste des écarts (vide = originaux intacts)."""
        problems = []
        for path, e in self.entries.items():
            f = Path(path)
            if not f.exists():
                problems.append(f"disparu : {path}")
                continue
            st = f.stat()
            if st.st_size != e["size"]:
                problems.append(f"taille modifiée : {path}")
            elif "sha256" in e and sha256_file(f) != e["sha256"]:
                problems.append(f"contenu modifié : {path}")
            elif st.st_mtime_ns != e["mtime_ns"]:
                problems.append(f"date modifiée : {path}")
        return problems

    def to_dict(self) -> Dict:
        return {"files": len(self.entries), "entries": self.entries}

    def save(self, path: Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=1), encoding="utf-8")
