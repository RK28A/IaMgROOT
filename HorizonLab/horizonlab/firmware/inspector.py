"""Module A - Firmware Inspector : orchestration de l'analyse d'un firmware."""
from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from horizonlab.core.models import Envelope
from horizonlab.core.workspace import OriginalsSeal, Workspace, sha256_file
from horizonlab.firmware import props as P
from horizonlab.firmware.extract import Preparer, find_kernel_files
from horizonlab.firmware.inventory import build_inventory
from horizonlab.firmware.kernel import kernel_info_from_file, modules_versions

log = logging.getLogger("horizonlab.firmware")
CHECKSUM_FILES = ("SHA256SUMS", "sha256sums.txt", "checksums.txt", "SHA256SUMS.txt")
_SUM_LINE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(.+)$")


def verify_checksum_files(src: Path) -> List[Dict[str, Any]]:
    """Vérifie les fichiers de sommes SHA-256 fournis avec le firmware (s'il y en a)."""
    src = Path(src)
    base = src if src.is_dir() else src.parent
    sums: List[Path] = [base / n for n in CHECKSUM_FILES if (base / n).is_file()]
    sums += sorted(base.glob("*.sha256")) + sorted(base.glob("*.sha256sum"))
    results = []
    for s in sums:
        for line in s.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _SUM_LINE.match(line.strip())
            if not m:
                # format « fichier.sha256 » contenant uniquement l'empreinte
                if re.fullmatch(r"[0-9a-fA-F]{64}", line.strip()) and s.suffix in (".sha256", ".sha256sum"):
                    target = s.with_suffix("")
                    expected = line.strip().lower()
                else:
                    continue
            else:
                expected, target = m.group(1).lower(), base / m.group(2).strip()
            if not Path(target).is_file():
                results.append({"file": str(target), "status": "missing", "list": s.name})
                continue
            actual = sha256_file(Path(target))
            results.append({"file": Path(target).name, "expected": expected, "actual": actual,
                            "status": "ok" if actual == expected else "MISMATCH", "list": s.name})
    return results


class FirmwareInspector:
    def __init__(self, workspace_root: Path, hash_files: bool = True, analyze_elf: bool = True,
                 max_elf: Optional[int] = None, extract_filesystems: bool = True,
                 verify_originals: bool = True, progress: Optional[Callable[[str], None]] = None):
        self.workspace_root = Path(workspace_root)
        self.hash_files = hash_files
        self.analyze_elf = analyze_elf
        self.max_elf = max_elf
        self.extract_filesystems = extract_filesystems
        self.verify_originals = verify_originals
        self.progress = progress or (lambda m: log.info(m))

    def inspect(self, src: Path, name: Optional[str] = None) -> Envelope:
        src = Path(src).resolve()
        if not src.exists():
            raise FileNotFoundError(src)
        name = name or src.name
        t0 = time.monotonic()
        ws = Workspace(self.workspace_root / P.safe_id(name), protected=[src])
        self.progress(f"[{name}] empreintes des originaux")
        seal = OriginalsSeal.capture([src])
        seal.save(ws.out / "originals_seal.json")

        self.progress(f"[{name}] préparation (images → copies de travail)")
        prep = Preparer(ws, extract_filesystems=self.extract_filesystems).prepare(src)
        root: Path = prep["root"]
        warnings = list(prep["warnings"])

        self.progress(f"[{name}] propriétés et modèle")
        props, origin = P.collect_props(root) if Path(root).exists() else ({}, {})
        model = P.identify_model(props, firmware_name=name)
        if not props:
            warnings.append("aucun build.prop trouvé : identification limitée")

        kernels = list(prep["kernels"])
        if Path(root).exists():
            for kf in find_kernel_files(root):
                try:
                    ki = kernel_info_from_file(kf)
                    ki.pop("_config_text", None)
                    ki["source"] = kf.relative_to(root).as_posix()
                    kernels.append(ki)
                except Exception as e:  # noqa: BLE001
                    warnings.append(f"noyau {kf.name} : {e}")
        if not any(k.get("version") for k in kernels):
            warnings.append("version du noyau non trouvée (aucune image boot / noyau lisible)")

        self.progress(f"[{name}] inventaire des fichiers")
        inv = build_inventory(root, ws, hash_files=self.hash_files, analyze_elf=self.analyze_elf,
                              max_elf=self.max_elf, progress=self.progress) if Path(root).exists() else {}
        kmods = modules_versions(root) if Path(root).exists() else {}

        checksums = verify_checksum_files(src)
        integrity: Dict[str, Any] = {"originals": seal.to_dict()["files"], "checksum_lists": checksums}
        if self.verify_originals:
            self.progress(f"[{name}] vérification : originaux intacts ?")
            problems = seal.verify()
            integrity["originals_unchanged"] = not problems
            integrity["problems"] = problems
            if problems:
                warnings.append("ATTENTION : des fichiers d'origine ont changé pendant l'analyse")
        input_hashes = {Path(k).name: v.get("sha256") for k, v in list(seal.entries.items())[:500]
                        if src.is_file() or v["size"] > 4 * 1024 * 1024}

        payload = {
            "firmware": {"name": name, "input": src.as_posix(), "input_mode": prep["mode"],
                         "root": Path(root).as_posix(), "workspace": ws.root.as_posix()},
            "model": model,
            "android": P.android_version(props),
            "key_props": {k: props[k] for k in P.KEY_PROPS if k in props},
            "props": props,
            "props_origin": origin,
            "kernel": kernels,
            "kernel_modules": {"count": len(kmods), "vermagic": sorted(set(kmods.values()))[:10]},
            "partitions": prep["partitions"],
            "avb": prep["avb"],
            "inventory": inv,
            "integrity": integrity,
            "large_input_hashes": input_hashes,
            "duration_s": round(time.monotonic() - t0, 2),
        }
        env = Envelope(kind="firmware_report", subject=name, payload=payload, warnings=warnings)
        env.save(ws.out / "firmware_report.json")
        self.progress(f"[{name}] terminé en {payload['duration_s']} s")
        return env
