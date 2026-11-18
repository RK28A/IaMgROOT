"""Modèles de données structurés partagés par tous les modules.

Chaque résultat d'analyse est enveloppé dans un ``Envelope`` versionné (``kind`` +
``schema_version``) afin que de nouvelles analyses puissent être ajoutées sans
réécrire les consommateurs (UI, rapports, comparaisons).

Le niveau de preuve (``Evidence``) distingue systématiquement :
  * OBSERVED   : fait lu directement dans un fichier / une sortie d'outil ;
  * KNOWN      : rôle documenté publiquement (AOSP, documentation Linux...) ;
  * HYPOTHESIS : déduction heuristique (nom, emplacement...) à confirmer.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from horizonlab import SCHEMA_VERSION, __version__


class Evidence(str, enum.Enum):
    OBSERVED = "observed"
    KNOWN = "known"
    HYPOTHESIS = "hypothesis"


@dataclasses.dataclass
class Finding:
    """Une constatation unitaire, toujours accompagnée de sa source."""

    key: str
    value: Any
    evidence: Evidence = Evidence.OBSERVED
    source: str = ""
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "evidence": self.evidence.value,
            "source": self.source,
            "note": self.note,
        }


def utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def to_jsonable(obj: Any) -> Any:
    """Conversion récursive (dataclasses, enums, Path, bytes, set) vers JSON."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        if hasattr(obj, "to_dict"):
            return to_jsonable(obj.to_dict())
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, Path):
        return obj.as_posix()
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted(to_jsonable(v) for v in obj)
    return obj


@dataclasses.dataclass
class Envelope:
    """Conteneur générique d'un résultat d'analyse sérialisable."""

    kind: str
    payload: Dict[str, Any]
    subject: str = ""
    created: str = dataclasses.field(default_factory=utcnow)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    warnings: List[str] = dataclasses.field(default_factory=list)
    errors: List[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "subject": self.subject,
            "created": self.created,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "payload": to_jsonable(self.payload),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")
        return path

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Envelope":
        missing = {"kind", "payload"} - set(d)
        if missing:
            raise ValueError(f"enveloppe invalide, champs manquants : {sorted(missing)}")
        return cls(
            kind=d["kind"],
            payload=d["payload"],
            subject=d.get("subject", ""),
            created=d.get("created", utcnow()),
            schema_version=d.get("schema_version", SCHEMA_VERSION),
            tool_version=d.get("tool_version", "?"),
            warnings=list(d.get("warnings", [])),
            errors=list(d.get("errors", [])),
        )

    @classmethod
    def load(cls, path: Path) -> "Envelope":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
