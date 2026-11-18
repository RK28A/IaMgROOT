"""Module B - Process & Service Mapper.

Assemble init (.rc), SELinux (CIL + contexts), VINTF, permissions, ELF (DT_NEEDED) et
manifestes d'APK pour produire une carte des services et un graphe des relations.
Chaque relation porte un niveau de preuve :
  * observed   - lu tel quel dans un fichier du firmware ;
  * known      - rôle documenté publiquement (config/components.json) ;
  * hypothesis - autorisé par la politique ou déduit d'un nom ; non prouvé à l'exécution.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from horizonlab.core.models import Envelope
from horizonlab.firmware import elfscan
from horizonlab.firmware.props import collect_props
from horizonlab.services import initrc, sepolicy, vintf
from horizonlab.services.graph import Graph
from horizonlab.services.paths import LibraryIndex, device_path, resolve

log = logging.getLogger("horizonlab.services")
CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


def load_knowledge(path: Optional[Path] = None) -> Dict[str, Any]:
    return json.loads(Path(path or CONFIG_DIR / "components.json").read_text(encoding="utf-8"))


def describe_role(name: str, path: str, kb: Dict[str, Any]) -> Dict[str, Any]:
    exe = Path(path).name
    for key in (name, exe):
        if key in kb.get("services", {}):
            r = kb["services"][key]
            return {"text": r["role"], "evidence": r.get("evidence", "known"), "source": r.get("source", "")}
    hints = []
    for h in kb.get("heuristics", []):
        if re.search(h["pattern"], f"{name} {exe}", re.I):
            hints.append(h["role"])
    if hints:
        return {"text": " ".join(dict.fromkeys(hints)), "evidence": "hypothesis",
                "source": "heuristique sur le nom (config/components.json)"}
    return {"text": "Rôle non établi.", "evidence": "hypothesis", "source": ""}


class ServiceMapper:
    def __init__(self, root: Path, max_lib_depth: int = 6, knowledge: Optional[Dict[str, Any]] = None):
        self.root = Path(root)
        self.max_lib_depth = max_lib_depth
        self.kb = knowledge or load_knowledge()
        self._elf_cache: Dict[str, Dict[str, Any]] = {}

    def _elf(self, rel: str) -> Dict[str, Any]:
        if rel not in self._elf_cache:
            p = self.root / rel
            try:
                self._elf_cache[rel] = elfscan.analyze_elf(p) if elfscan.is_elf(p) else {"error": "pas un ELF"}
            except Exception as e:  # noqa: BLE001
                self._elf_cache[rel] = {"error": str(e)}
        return self._elf_cache[rel]

    def _libraries(self, exe_rel: str, index: LibraryIndex) -> Dict[str, Any]:
        info = self._elf(exe_rel)
        is64 = info.get("class", 64) == 64
        direct = list(info.get("needed") or [])
        resolved: Dict[str, Optional[str]] = {}
        missing: Set[str] = set()
        edges: List[tuple] = []
        frontier = [(exe_rel, n, 1) for n in direct]
        seen: Set[str] = set()
        while frontier:
            req, name, depth = frontier.pop(0)
            edges.append((req, name))
            if name in seen:
                continue
            seen.add(name)
            path = index.find(name, req, is64)
            resolved[name] = path
            if path is None:
                missing.add(name)
                continue
            if depth < self.max_lib_depth:
                for sub in self._elf(path).get("needed") or []:
                    frontier.append((path, sub, depth + 1))
        return {"direct": direct, "transitive": sorted(n for n in resolved if n not in direct),
                "resolved": resolved, "missing": sorted(missing), "edges": edges}

    def run(self, subject: str = "") -> Envelope:
        root = self.root
        warnings: List[str] = []
        props, _ = collect_props(root)
        rc = initrc.parse_tree(root)
        pol, ctx, sel_extra = sepolicy.load_policy(root)
        manifests = vintf.find_vintf(root)
        perms = vintf.find_permissions(root)
        index = LibraryIndex(root)
        if not rc["files"]:
            warnings.append("aucun fichier .rc trouvé")
        if not pol.files:
            warnings.append("aucune politique SELinux CIL textuelle trouvée")
        starts = initrc.start_edges(rc["actions"], rc["services"])
        registrations = pol.service_registrations()
        calls = pol.binder_calls()
        g = Graph()
        services_out = []
        for name, s in sorted(rc["services"].items()):
            exe_dev = initrc.expand_props(s.path, props)
            exe_rel = resolve(root, exe_dev)
            sid = g.node(f"service:{name}", "service", name, file=s.file)
            entry: Dict[str, Any] = s.to_dict()
            entry["executable"] = {"device_path": exe_dev, "tree_path": exe_rel, "found": exe_rel is not None}
            if exe_rel:
                eid = g.node(f"exe:{exe_dev}", "executable", Path(exe_dev).name, path=exe_dev)
                g.edge(sid, eid, "runs", "observed", s.file)
                info = self._elf(exe_rel)
                entry["executable"]["elf"] = {k: info.get(k) for k in ("machine", "class", "type", "interpreter",
                                                                         "hardening", "notable_imports", "error")}
                libs = self._libraries(exe_rel, index)
                entry["libraries"] = {k: libs[k] for k in ("direct", "transitive", "missing")}
                for n in libs["direct"]:
                    lid = g.node(f"lib:{n}", "library", n, path=libs["resolved"].get(n),
                                 missing=n in libs["missing"])
                    g.edge(eid, lid, "links", "observed", f"DT_NEEDED de {exe_rel}")
            else:
                entry["libraries"] = {"direct": [], "transitive": [], "missing": []}
                warnings.append(f"service {name} : exécutable {exe_dev} absent de l'arborescence")
            # --- SELinux
            exec_label = ctx.file_label(exe_dev) if ctx.file else None
            domain, dsrc = None, None
            if s.seclabel:
                domain, dsrc = sepolicy.label_type(s.seclabel), "seclabel (init .rc)"
            elif exec_label:
                domain = pol.domain_for_exec(sepolicy.label_type(exec_label))
                dsrc = "typetransition init → domaine (CIL)" if domain else None
            entry["selinux"] = {"exec_label": exec_label, "domain": domain, "domain_source": dsrc}
            if domain:
                entry["selinux"].update(pol.stats_for(domain))
                did = g.node(f"domain:{domain}", "domain", domain)
                g.edge(sid, did, "runs_in", "observed", dsrc or "")
            # --- Binder : interfaces déclarées dans le .rc
            for itf in s.interfaces:
                bid = g.node(f"binder:{itf['name']}", "binder", itf["name"], btype=itf["kind"])
                g.edge(sid, bid, "declares_interface", "observed", s.file)
            # --- sockets
            for so in s.sockets:
                if so.get("name"):
                    soid = g.node(f"socket:{so['name']}", "socket", so["name"])
                    g.edge(sid, soid, "creates_socket", "observed", s.file)
            # --- démarrage / redémarrage
            entry["started_by"] = [e for e in starts if e["service"] == name]
            for e in entry["started_by"]:
                tid = g.node(f"trigger:{e['trigger']}", "trigger", f"on {e['trigger']}")
                g.edge(tid, sid, e["how"], "observed", e["file"])
            for r in s.onrestart:
                t = r.split()
                if t and t[0] == "restart" and len(t) > 1:
                    g.edge(sid, f"service:{t[-1]}", "onrestart_restarts", "observed", s.file)
            entry["role"] = describe_role(name, exe_dev, self.kb)
            services_out.append(entry)
        # --- services Binder (contexts + VINTF) et domaines qui peuvent les enregistrer
        binder_services: List[Dict[str, Any]] = []
        type_to_domains: Dict[str, Set[str]] = {}
        for d, t in registrations:
            type_to_domains.setdefault(t, set()).add(d)
        for kind, table in (("service", ctx.service), ("hwservice", ctx.hwservice), ("vndservice", ctx.vndservice)):
            for name, label in sorted(table.items()):
                t = sepolicy.label_type(label)
                regs = sorted(type_to_domains.get(t, set()))
                binder_services.append({"name": name, "kind": kind, "selinux_type": t,
                                        "registrable_by_domains": regs})
                if name == "*":
                    continue
                bid = g.node(f"binder:{name}", "binder", name, btype=kind, selinux_type=t)
                for d in regs:
                    g.edge(g.node(f"domain:{d}", "domain", d), bid, "may_register",
                           "hypothesis", "allow … service_manager add (CIL)")
        for itf in vintf.binder_interface_names(manifests):
            bid = g.node(f"binder:{itf['name']}", "binder", itf["name"], btype=f"vintf/{itf['format']}")
            hid = g.node(f"hal:{itf['hal']}", "hal", itf["hal"])
            g.edge(hid, bid, "declares_instance", "observed", itf["file"])
            binder_services.append({"name": itf["name"], "kind": f"vintf-{itf['format']}", "hal": itf["hal"],
                                    "declared_in": itf["file"]})
        # rattacher les déclarations VINTF aux interfaces init (nom AIDL « pkg.I/inst »)
        for n in list(g.nodes):
            if n.startswith("binder:") and "/" in n:
                alt = n.replace("binder:", "binder:", 1)
                pkg_inst = alt.split(":", 1)[1]
                for h in list(g.nodes):
                    if h.startswith("hal:") and pkg_inst.startswith(h[4:] + "."):
                        g.edge(h, n, "declares_instance", "observed", "manifeste VINTF")
        for a, b in sorted(set(calls)):
            if a != b:
                g.edge(g.node(f"domain:{a}", "domain", a), g.node(f"domain:{b}", "domain", b),
                       "binder_call_allowed", "hypothesis", "allow … binder call (CIL)")
        payload = {
            "root": root.as_posix(),
            "init": {"files": rc["files"], "service_count": len(rc["services"]), "action_count": len(rc["actions"]),
                     "imports": rc["imports"], "errors": rc["errors"], "duplicates": rc["duplicates"],
                     "triggers": sorted({a.trigger for a in rc["actions"]})},
            "services": services_out,
            "binder_services": binder_services,
            "vintf": manifests,
            "selinux": {**pol.summary(), "contexts_files": ctx.sources, "file_context_rules": len(ctx.file),
                        "property_context_rules": ctx.property_count, **sel_extra},
            "permissions": perms,
            "apks": self._apks(),
            "graph": g.to_dict(),
            "graph_stats": g.stats(),
            "evidence_legend": {"observed": "lu dans un fichier du firmware",
                                "known": "rôle documenté publiquement",
                                "hypothesis": "autorisé par la politique ou déduit d'un nom ; non vérifié à l'exécution"},
        }
        return Envelope(kind="service_map", subject=subject or root.name, payload=payload, warnings=warnings)

    def _apks(self) -> List[Dict[str, Any]]:
        from horizonlab.services.axml import read_apk_manifest

        out = []
        for p in sorted(self.root.rglob("*.apk")):
            try:
                m = read_apk_manifest(p)
            except Exception as e:  # noqa: BLE001
                m = {"error": str(e)}
            m["path"] = p.relative_to(self.root).as_posix()
            m["device_path"] = device_path(m["path"])
            m["privileged"] = "/priv-app/" in m["device_path"]
            out.append(m)
        return out


def compare_service_maps(a: Envelope, b: Envelope) -> Envelope:
    sa = {s["name"]: s for s in a.payload["services"]}
    sb = {s["name"]: s for s in b.payload["services"]}
    changed = []
    for n in sorted(set(sa) & set(sb)):
        x, y = sa[n], sb[n]
        diffs = {}
        for k in ("path", "user", "groups", "capabilities", "classes", "flags", "seclabel"):
            if x.get(k) != y.get(k):
                diffs[k] = {"a": x.get(k), "b": y.get(k)}
        if x["selinux"].get("domain") != y["selinux"].get("domain"):
            diffs["domain"] = {"a": x["selinux"].get("domain"), "b": y["selinux"].get("domain")}
        if set(x["libraries"]["direct"]) != set(y["libraries"]["direct"]):
            diffs["libraries"] = {"added": sorted(set(y["libraries"]["direct"]) - set(x["libraries"]["direct"])),
                                  "removed": sorted(set(x["libraries"]["direct"]) - set(y["libraries"]["direct"]))}
        if [i["name"] for i in x["interfaces"]] != [i["name"] for i in y["interfaces"]]:
            diffs["interfaces"] = {"a": [i["name"] for i in x["interfaces"]], "b": [i["name"] for i in y["interfaces"]]}
        if diffs:
            changed.append({"service": n, "changes": diffs})
    ba = {s["name"] for s in a.payload["binder_services"]}
    bb = {s["name"] for s in b.payload["binder_services"]}
    pa = set(a.payload["selinux"].get("permissive_domains", []))
    pb = set(b.payload["selinux"].get("permissive_domains", []))
    fa = set(a.payload["permissions"].get("features", []))
    fb = set(b.payload["permissions"].get("features", []))
    payload = {
        "a": a.subject, "b": b.subject,
        "services": {"only_a": sorted(set(sa) - set(sb)), "only_b": sorted(set(sb) - set(sa)),
                     "common": len(set(sa) & set(sb)), "changed": changed},
        "binder_services": {"only_a": sorted(ba - bb), "only_b": sorted(bb - ba)},
        "selinux": {"permissive_only_a": sorted(pa - pb), "permissive_only_b": sorted(pb - pa),
                    "allow_rules": {"a": a.payload["selinux"].get("allow_rules"),
                                    "b": b.payload["selinux"].get("allow_rules")}},
        "features": {"only_a": sorted(fa - fb), "only_b": sorted(fb - fa)},
        "triggers": {"only_a": sorted(set(a.payload["init"]["triggers"]) - set(b.payload["init"]["triggers"])),
                     "only_b": sorted(set(b.payload["init"]["triggers"]) - set(a.payload["init"]["triggers"]))},
    }
    return Envelope(kind="service_comparison", subject=f"{a.subject} vs {b.subject}", payload=payload)
