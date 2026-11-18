"""Lecture des fichiers de propriétés Android et identification du modèle de casque."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from horizonlab.core.models import Evidence, Finding

# Emplacements standards (relatifs à la racine d'une arborescence extraite).
PROP_FILES = [
    "system/build.prop", "system/system/build.prop", "build.prop",
    "vendor/build.prop", "system/vendor/build.prop", "odm/build.prop", "vendor/odm/etc/build.prop",
    "odm/etc/build.prop", "product/build.prop", "system/product/build.prop", "product/etc/build.prop",
    "system_ext/build.prop", "system/system_ext/build.prop", "system_ext/etc/build.prop",
    "vendor_dlkm/etc/build.prop", "odm_dlkm/etc/build.prop", "system_dlkm/etc/build.prop",
    "default.prop", "prop.default", "system/etc/prop.default", "vendor/default.prop",
]

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


def parse_prop_text(text: str) -> Dict[str, str]:
    props: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("import "):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    return props


def collect_props(root: Path) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Fusionne les build.prop trouvés ; renvoie (propriétés, origine_de_chaque_propriété)."""
    root = Path(root)
    merged: Dict[str, str] = {}
    origin: Dict[str, str] = {}
    candidates = [root / p for p in PROP_FILES]
    # Recherche complémentaire des build.prop non standards (profondeur limitée).
    for extra in sorted(root.glob("*/*/build.prop")) + sorted(root.glob("*/build.prop")):
        if extra not in candidates:
            candidates.append(extra)
    for f in candidates:
        if f.is_file():
            try:
                props = parse_prop_text(f.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            rel = f.relative_to(root).as_posix()
            for k, v in props.items():
                if k not in merged:  # première occurrence = la plus prioritaire de la liste
                    merged[k] = v
                    origin[k] = rel
    return merged, origin


def load_device_db(path: Optional[Path] = None) -> Dict[str, Any]:
    return json.loads(Path(path or CONFIG_DIR / "devices.json").read_text(encoding="utf-8"))


def identify_model(props: Dict[str, str], firmware_name: str = "",
                   db: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Score pondéré par signal ; chaque signal retenu est conservé comme preuve."""
    db = db or load_device_db()
    weights = db.get("signal_weights", {})
    scores: Dict[str, int] = {}
    signals: List[Finding] = []
    for m in db["models"]:
        codes = {c.lower() for c in m.get("codenames", [])}
        for key in ("ro.product.device", "ro.product.vendor.device", "ro.product.system.device",
                    "ro.build.product", "ro.product.name"):
            v = props.get(key, "").lower()
            if v and (v in codes or any(v.startswith(c) for c in codes)):
                scores[m["id"]] = scores.get(m["id"], 0) + weights.get(key, 1)
                signals.append(Finding(key, props[key], Evidence.OBSERVED, "build.prop",
                                       f"correspond au nom de code {sorted(codes)} de {m['name']}"))
        model = props.get("ro.product.model", "")
        if model and any(model.strip().lower() == s.lower() for s in m.get("model_strings", [])):
            scores[m["id"]] = scores.get(m["id"], 0) + weights.get("ro.product.model", 1)
            signals.append(Finding("ro.product.model", model, Evidence.OBSERVED, "build.prop",
                                   f"chaîne modèle de {m['name']}"))
        plat = props.get("ro.board.platform", "").lower()
        if plat and plat in [p.lower() for p in m.get("board_platforms", [])]:
            scores[m["id"]] = scores.get(m["id"], 0) + weights.get("ro.board.platform", 1)
            signals.append(Finding("ro.board.platform", plat, Evidence.HYPOTHESIS, "build.prop",
                                   f"plateforme associée (non exclusive) à {m['name']}"))
        if firmware_name and any(firmware_name.lower().startswith(p) for p in m.get("firmware_prefixes", [])):
            scores[m["id"]] = scores.get(m["id"], 0) + weights.get("firmware_name", 1)
            signals.append(Finding("firmware_name", firmware_name, Evidence.HYPOTHESIS, "nom du répertoire",
                                   f"préfixe conventionnel de {m['name']} (indice faible)"))
    if not scores:
        return {"model_id": None, "model_name": None, "confidence": "none", "scores": {},
                "signals": [s.to_dict() for s in signals]}
    best = max(scores, key=lambda k: scores[k])
    top = scores[best]
    second = max([v for k, v in scores.items() if k != best] or [0])
    strong = any(s.evidence == Evidence.OBSERVED and s.key != "firmware_name" for s in signals)
    if top >= 5 and strong and top > second:
        conf = "high"
    elif top > second:
        conf = "medium" if strong else "low"
    else:
        conf = "ambiguous"
    m = next(x for x in db["models"] if x["id"] == best)
    return {"model_id": best, "model_name": m["name"], "soc": m.get("soc"), "confidence": conf,
            "scores": scores, "signals": [s.to_dict() for s in signals]}


KEY_PROPS = [
    "ro.build.fingerprint", "ro.system.build.fingerprint", "ro.vendor.build.fingerprint",
    "ro.build.id", "ro.build.display.id", "ro.build.version.incremental", "ro.build.version.release",
    "ro.build.version.sdk", "ro.build.version.security_patch", "ro.vendor.build.security_patch",
    "ro.build.type", "ro.build.tags", "ro.build.date", "ro.build.date.utc", "ro.build.description",
    "ro.product.model", "ro.product.device", "ro.product.name", "ro.product.manufacturer",
    "ro.product.brand", "ro.board.platform", "ro.hardware", "ro.product.cpu.abilist",
    "ro.vndk.version", "ro.product.first_api_level", "ro.board.first_api_level",
    "ro.board.api_level", "ro.treble.enabled", "ro.apex.updatable", "ro.crypto.state",
    "ro.debuggable", "ro.secure", "ro.adb.secure", "ro.build.ab_update", "ro.virtual_ab.enabled",
    "ro.boot.dynamic_partitions", "ro.ota.version", "ro.vros.build.version",
]


def android_version(props: Dict[str, str]) -> Dict[str, Optional[str]]:
    return {
        "release": props.get("ro.build.version.release") or props.get("ro.system.build.version.release"),
        "sdk": props.get("ro.build.version.sdk") or props.get("ro.system.build.version.sdk"),
        "security_patch": props.get("ro.build.version.security_patch"),
        "vendor_security_patch": props.get("ro.vendor.build.security_patch"),
        "build_id": props.get("ro.build.id"),
        "incremental": props.get("ro.build.version.incremental"),
        "fingerprint": props.get("ro.build.fingerprint") or props.get("ro.system.build.fingerprint"),
        "vndk": props.get("ro.vndk.version"),
        "build_type": props.get("ro.build.type"),
    }


_SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]+")


def safe_id(s: str) -> str:
    return _SAFE_ID.sub("_", s).strip("_") or "firmware"
