"""Lecture des politiques SELinux d'Android (CIL texte + fichiers *_contexts).

Seules des sources textuelles sont analysées (plat/system_ext/product/vendor/odm
``*.cil`` et ``*_contexts``). La politique binaire ``precompiled_sepolicy`` n'est pas
décompilée ici : sa présence et son empreinte sont simplement signalées.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

SExpr = Union[str, List["SExpr"]]


def tokenize_cil(text: str) -> Iterator[str]:
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
        elif c == ";":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c in "()":
            yield c
            i += 1
        elif c == '"':
            j = text.find('"', i + 1)
            j = n - 1 if j < 0 else j
            yield text[i:j + 1]
            i = j + 1
        else:
            j = i
            while j < n and text[j] not in " \t\r\n()":
                j += 1
            yield text[i:j]
            i = j


def parse_cil(text: str) -> List[SExpr]:
    stack: List[List[SExpr]] = [[]]
    for t in tokenize_cil(text):
        if t == "(":
            stack.append([])
        elif t == ")":
            if len(stack) > 1:
                done = stack.pop()
                stack[-1].append(done)
        else:
            stack[-1].append(t)
    while len(stack) > 1:  # parenthèses non fermées : on tolère
        done = stack.pop()
        stack[-1].append(done)
    return stack[0]


def _flat(x: SExpr) -> List[str]:
    if isinstance(x, str):
        return [x]
    out: List[str] = []
    for y in x:
        out.extend(_flat(y))
    return out


VERSIONED = re.compile(r"_\d+_\d+$")


def unversion(t: str) -> str:
    """Les types de politique plateforme sont suffixés (ex. ``surfaceflinger_30_0``)."""
    return VERSIONED.sub("", t)


class Policy:
    def __init__(self) -> None:
        self.types: set = set()
        self.attributes: Dict[str, set] = {}
        self.allows: List[Dict[str, Any]] = []
        self.neverallows = 0
        self.transitions: List[Dict[str, str]] = []
        self.permissive: set = set()
        self.files: List[str] = []

    def load_cil(self, text: str, source: str) -> None:
        self.files.append(source)
        for e in parse_cil(text):
            if not isinstance(e, list) or not e or not isinstance(e[0], str):
                continue
            kw = e[0]
            if kw == "type" and len(e) > 1:
                self.types.add(e[1])
            elif kw == "typeattributeset" and len(e) > 2:
                self.attributes.setdefault(e[1], set()).update(t for t in _flat(e[2]) if t not in ("and", "or", "not", "all"))
            elif kw == "typeattribute" and len(e) > 1:
                self.attributes.setdefault(e[1], set())
            elif kw == "allow" and len(e) >= 4:
                cls_perm = e[3]
                cls = cls_perm[0] if isinstance(cls_perm, list) and cls_perm else str(cls_perm)
                perms = _flat(cls_perm[1]) if isinstance(cls_perm, list) and len(cls_perm) > 1 else []
                self.allows.append({"src": e[1] if isinstance(e[1], str) else "(expr)",
                                    "tgt": e[2] if isinstance(e[2], str) else "(expr)",
                                    "cls": cls, "perms": perms, "source": source})
            elif kw == "neverallow":
                self.neverallows += 1
            elif kw == "typetransition" and len(e) >= 5:
                # (typetransition src exec_type class [name] new_type)
                if e[3] == "process":
                    self.transitions.append({"src": e[1], "exec": e[2], "domain": e[-1], "source": source})
            elif kw == "typepermissive" and len(e) > 1:
                self.permissive.add(e[1])

    # ------------------------------------------------------------------ requêtes
    def expand(self, t: str) -> set:
        return self.attributes.get(t, {t})

    def domain_for_exec(self, exec_type: str) -> Optional[str]:
        for tr in self.transitions:
            if unversion(tr["exec"]) == unversion(exec_type) and unversion(tr["src"]) == "init":
                return unversion(tr["domain"])
        return None

    def service_registrations(self) -> List[Tuple[str, str]]:
        """(domaine, type_de_service) d'après ``allow D T (service_manager (add ...))``."""
        out = []
        for a in self.allows:
            if a["cls"] in ("service_manager", "hwservice_manager", "vndservice_manager") and "add" in a["perms"]:
                for d in self.expand(a["src"]):
                    out.append((unversion(d), unversion(a["tgt"])))
        return out

    def binder_calls(self) -> List[Tuple[str, str]]:
        out = []
        for a in self.allows:
            if a["cls"] == "binder" and "call" in a["perms"]:
                for s in self.expand(a["src"]):
                    for t in self.expand(a["tgt"]):
                        out.append((unversion(s), unversion(t if t != "self" else s)))
        return out

    def stats_for(self, domain: str) -> Dict[str, Any]:
        rules = [a for a in self.allows if unversion(a["src"]) == domain]
        classes: Dict[str, int] = {}
        for r in rules:
            classes[r["cls"]] = classes.get(r["cls"], 0) + 1
        return {"allow_rules": len(rules), "classes": classes, "permissive": domain in
                {unversion(p) for p in self.permissive}}

    def summary(self) -> Dict[str, Any]:
        return {"files": self.files, "types": len(self.types), "attributes": len(self.attributes),
                "allow_rules": len(self.allows), "neverallow_rules": self.neverallows,
                "process_transitions": len(self.transitions),
                "permissive_domains": sorted(unversion(p) for p in self.permissive)}


CONTEXT_FILES = {
    "file_contexts": "file", "service_contexts": "service", "hwservice_contexts": "hwservice",
    "vndservice_contexts": "vndservice", "property_contexts": "property", "seapp_contexts": "seapp",
}


def parse_contexts_line(line: str) -> Optional[Tuple[str, str]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    if len(parts) < 2:
        return None
    return parts[0], parts[-1]


def label_type(label: str) -> str:
    """``u:object_r:foo_exec:s0`` → ``foo_exec``"""
    p = label.split(":")
    return p[2] if len(p) >= 3 else label


class Contexts:
    def __init__(self) -> None:
        self.file: List[Tuple[re.Pattern, str, str]] = []
        self.service: Dict[str, str] = {}
        self.hwservice: Dict[str, str] = {}
        self.vndservice: Dict[str, str] = {}
        self.property_count = 0
        self.sources: List[str] = []

    def load(self, path: Path, rel: str) -> None:
        name = path.name
        # suffixes les plus longs d'abord : « hwservice_contexts » avant « service_contexts »
        kind = next((CONTEXT_FILES[suf] for suf in sorted(CONTEXT_FILES, key=len, reverse=True)
                     if name.endswith(suf)), None)
        if not kind:
            return
        self.sources.append(rel)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            pl = parse_contexts_line(line)
            if not pl:
                continue
            key, label = pl
            if kind == "file":
                try:
                    self.file.append((re.compile(key + r"\Z"), label, rel))
                except re.error:
                    continue
            elif kind == "service":
                self.service[key] = label
            elif kind == "hwservice":
                self.hwservice[key] = label
            elif kind == "vndservice":
                self.vndservice[key] = label
            elif kind == "property":
                self.property_count += 1

    def file_label(self, path: str) -> Optional[str]:
        # Règle SELinux : la dernière correspondance l'emporte (approximation : ordre de lecture).
        found = None
        for rx, label, _src in self.file:
            if rx.match(path):
                found = label
        return found


def load_policy(root: Path) -> Tuple[Policy, Contexts, Dict[str, Any]]:
    root = Path(root)
    pol, ctx = Policy(), Contexts()
    extra: Dict[str, Any] = {"precompiled_sepolicy": []}
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if "selinux" not in rel and "sepolicy" not in p.name and not p.name.endswith("_contexts"):
            continue
        if p.suffix == ".cil":
            pol.load_cil(p.read_text(encoding="utf-8", errors="replace"), rel)
        elif p.name.endswith(tuple(CONTEXT_FILES)):
            ctx.load(p, rel)
        elif p.name.startswith("precompiled_sepolicy") and not p.name.endswith(".sha256"):
            from horizonlab.core.workspace import sha256_file

            extra["precompiled_sepolicy"].append({"path": rel, "sha256": sha256_file(p), "size": p.stat().st_size})
    return pol, ctx, extra
