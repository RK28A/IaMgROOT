"""Détection des outils externes (optionnels) et exécution encadrée de sous-processus."""
from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
from typing import Dict, List, Optional, Sequence

KNOWN_TOOLS = {
    # nom logique : (exécutables candidats, rôle)
    "adb": (["adb"], "communication avec le casque (module D)"),
    "debugfs": (["debugfs"], "extraction ext4 (repli : lecteur ext4 Python intégré)"),
    "fsck.erofs": (["fsck.erofs"], "extraction EROFS"),
    "dump.erofs": (["dump.erofs"], "métadonnées EROFS"),
    "simg2img": (["simg2img"], "conversion sparse (repli : implémentation Python intégrée)"),
    "lz4": (["lz4"], "décompression noyau / ramdisk LZ4"),
    "qemu-aarch64": (["qemu-aarch64", "qemu-aarch64-static"], "exécution de binaires ARM64 en mode utilisateur (module C)"),
    "qemu-system-aarch64": (["qemu-system-aarch64"], "émulation système ARM64 (module C)"),
    "emulator": (["emulator"], "Android Emulator du SDK (module C)"),
    "vmlinux-to-elf": (["vmlinux-to-elf"], "reconstruction ELF du noyau"),
    "analyzeHeadless": (["analyzeHeadless", "analyzeHeadless.bat"], "Ghidra headless"),
    "readelf": (["readelf", "llvm-readelf"], "contrôle croisé ELF"),
    "unshare": (["unshare"], "isolation réseau du laboratoire (Linux)"),
    "aapt": (["aapt"], "construction APK"),
    "apksigner": (["apksigner"], "signature APK"),
}


def which(name: str) -> Optional[str]:
    cands, _ = KNOWN_TOOLS.get(name, ([name], ""))
    env_override = os.environ.get("HORIZONLAB_" + name.upper().replace("-", "_").replace(".", "_"))
    if env_override and os.path.exists(env_override):
        return env_override
    for c in cands:
        p = shutil.which(c)
        if p:
            return p
    return None


def tool_report() -> Dict[str, Dict[str, Optional[str]]]:
    return {name: {"path": which(name), "role": role} for name, (_, role) in KNOWN_TOOLS.items()}


@dataclasses.dataclass
class RunResult:
    argv: List[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_s: float = 0.0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def to_dict(self):
        return dataclasses.asdict(self)


def run(argv: Sequence[str], timeout: float = 60, cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None, input_bytes: Optional[bytes] = None) -> RunResult:
    """Exécute une commande sans shell, avec délai maximal ; ne lève pas d'exception."""
    import time

    t0 = time.monotonic()
    try:
        p = subprocess.run(list(argv), capture_output=True, timeout=timeout, cwd=cwd, env=env,
                           input=input_bytes)
        return RunResult(list(argv), p.returncode, p.stdout.decode("utf-8", "replace"),
                         p.stderr.decode("utf-8", "replace"), False, time.monotonic() - t0)
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = (e.stderr or b"").decode("utf-8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return RunResult(list(argv), None, out, err, True, time.monotonic() - t0)
    except FileNotFoundError as e:
        return RunResult(list(argv), None, "", f"introuvable : {e}", False, time.monotonic() - t0)
