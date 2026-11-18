"""Analyseur du langage init d'Android (fichiers .rc).

Référence : system/core/init/README.md (AOSP). Sections ``service``, ``on``, ``import`` ;
les lignes de continuation (``\\``) et les commentaires sont gérés. Le résultat conserve
le fichier et la ligne d'origine de chaque déclaration (traçabilité des faits observés).
"""
from __future__ import annotations

import dataclasses
import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional

PROP_REF = re.compile(r"\$\{([^}:]+)(?::-([^}]*))?\}")

# Répertoires lus automatiquement par init (Android 9+), selon le README AOSP.
DEFAULT_INIT_DIRS = ["system/etc/init", "system_ext/etc/init", "vendor/etc/init", "odm/etc/init",
                     "product/etc/init", "apex"]


@dataclasses.dataclass
class Service:
    name: str
    path: str
    args: List[str]
    file: str
    line: int
    classes: List[str] = dataclasses.field(default_factory=lambda: ["default"])
    user: Optional[str] = None
    groups: List[str] = dataclasses.field(default_factory=list)
    capabilities: List[str] = dataclasses.field(default_factory=list)
    seclabel: Optional[str] = None
    sockets: List[Dict[str, str]] = dataclasses.field(default_factory=list)
    interfaces: List[Dict[str, str]] = dataclasses.field(default_factory=list)
    onrestart: List[str] = dataclasses.field(default_factory=list)
    flags: List[str] = dataclasses.field(default_factory=list)  # disabled, oneshot, critical...
    options: Dict[str, List[str]] = dataclasses.field(default_factory=dict)
    overrides: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Action:
    trigger: str
    commands: List[str]
    file: str
    line: int

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class RcFile:
    path: str
    services: List[Service]
    actions: List[Action]
    imports: List[str]
    errors: List[str]


FLAG_OPTIONS = {"disabled", "oneshot", "critical", "updatable", "override", "console",
                "restart_period", "gentle_kill", "reboot_on_failure", "stdio_to_kmsg"}


def _logical_lines(text: str):
    buf, start = "", None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if start is None:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        stripped = buf.strip()
        if stripped and not stripped.startswith("#"):
            yield start, stripped
        buf, start = "", None


def _split(line: str) -> List[str]:
    try:
        return shlex.split(line, comments=True, posix=True)
    except ValueError:
        return line.split()


def parse_rc(text: str, file: str = "<memory>") -> RcFile:
    services: List[Service] = []
    actions: List[Action] = []
    imports: List[str] = []
    errors: List[str] = []
    current: Optional[Any] = None
    for lineno, line in _logical_lines(text):
        tok = _split(line)
        if not tok:
            continue
        kw = tok[0]
        if kw == "service":
            if len(tok) < 3:
                errors.append(f"{file}:{lineno}: service incomplet")
                current = None
                continue
            current = Service(name=tok[1], path=tok[2], args=tok[3:], file=file, line=lineno)
            services.append(current)
        elif kw == "on":
            current = Action(trigger=" ".join(tok[1:]), commands=[], file=file, line=lineno)
            actions.append(current)
        elif kw == "import":
            if len(tok) >= 2:
                imports.append(tok[1])
            current = None
        elif isinstance(current, Service):
            _service_option(current, tok)
        elif isinstance(current, Action):
            current.commands.append(" ".join(tok))
        else:
            errors.append(f"{file}:{lineno}: ligne hors section : {line[:80]}")
    return RcFile(file, services, actions, imports, errors)


def _service_option(s: Service, tok: List[str]) -> None:
    opt, args = tok[0], tok[1:]
    if opt == "class":
        s.classes = args or ["default"]
    elif opt == "user":
        s.user = args[0] if args else None
    elif opt == "group":
        s.groups = args
    elif opt == "capabilities":
        s.capabilities = args
    elif opt == "seclabel":
        s.seclabel = args[0] if args else None
    elif opt == "socket":
        keys = ["name", "type", "perm", "user", "group", "seclabel"]
        s.sockets.append({k: v for k, v in zip(keys, args)})
    elif opt == "interface":
        if len(args) >= 2:
            s.interfaces.append({"kind": args[0], "name": args[1]})
        elif args:
            s.interfaces.append({"kind": "hidl", "name": args[0]})
    elif opt == "onrestart":
        s.onrestart.append(" ".join(args))
    elif opt in FLAG_OPTIONS and not args:
        s.flags.append(opt)
        if opt == "override":
            s.overrides = True
    else:
        s.options.setdefault(opt, []).extend(args or ["true"])


def expand_props(s: str, props: Dict[str, str]) -> str:
    def rep(m):
        return props.get(m.group(1), m.group(2) if m.group(2) is not None else m.group(0))

    return PROP_REF.sub(rep, s)


def find_rc_files(root: Path) -> List[Path]:
    """Tous les .rc de l'arborescence (init.rc principal, répertoires init, ramdisks, apex)."""
    root = Path(root)
    out = sorted(p for p in root.rglob("*.rc") if p.is_file())
    return out


def parse_tree(root: Path) -> Dict[str, Any]:
    root = Path(root)
    services: Dict[str, Service] = {}
    actions: List[Action] = []
    imports: List[Dict[str, str]] = []
    errors: List[str] = []
    duplicates: List[Dict[str, str]] = []
    files = []
    for f in find_rc_files(root):
        rel = f.relative_to(root).as_posix()
        try:
            rc = parse_rc(f.read_text(encoding="utf-8", errors="replace"), rel)
        except OSError as e:
            errors.append(f"{rel}: {e}")
            continue
        files.append(rel)
        for s in rc.services:
            if s.name in services and not s.overrides:
                duplicates.append({"service": s.name, "first": services[s.name].file, "second": rel})
                continue
            services[s.name] = s
        actions.extend(rc.actions)
        imports.extend({"file": rel, "import": i} for i in rc.imports)
        errors.extend(rc.errors)
    return {"files": files, "services": services, "actions": actions, "imports": imports,
            "errors": errors, "duplicates": duplicates}


def start_edges(actions: List[Action], services: Dict[str, Service]) -> List[Dict[str, str]]:
    """Qui démarre quoi : déclencheur → service (start / restart / class_start / enable)."""
    edges: List[Dict[str, str]] = []
    by_class: Dict[str, List[str]] = {}
    for s in services.values():
        for c in s.classes:
            by_class.setdefault(c, []).append(s.name)
    for a in actions:
        for c in a.commands:
            t = c.split()
            if not t:
                continue
            if t[0] in ("start", "restart", "enable") and len(t) > 1:
                edges.append({"trigger": a.trigger, "service": t[-1], "how": t[0], "file": a.file})
            elif t[0] in ("class_start", "class_start_post_data", "class_restart") and len(t) > 1:
                for sname in by_class.get(t[1], []):
                    edges.append({"trigger": a.trigger, "service": sname, "how": f"{t[0]} {t[1]}",
                                  "file": a.file})
            elif t[0] == "trigger" and len(t) > 1:
                edges.append({"trigger": a.trigger, "service": "", "how": "trigger", "target_trigger": t[1],
                              "file": a.file})
    return edges
