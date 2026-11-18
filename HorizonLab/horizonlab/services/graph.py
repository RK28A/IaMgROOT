"""Graphe orienté des composants (nœuds typés, arêtes étiquetées avec niveau de preuve)."""
from __future__ import annotations

from collections import deque
from typing import Any, Dict, Iterable, List, Optional, Set


class Graph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._ekeys: Set[tuple] = set()

    def node(self, nid: str, kind: str, label: Optional[str] = None, **attrs) -> str:
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "kind": kind, "label": label or nid.split(":", 1)[-1], **attrs}
        else:
            self.nodes[nid].update({k: v for k, v in attrs.items() if v is not None})
        return nid

    def edge(self, src: str, dst: str, rel: str, evidence: str = "observed", source: str = "") -> None:
        key = (src, dst, rel)
        if key in self._ekeys:
            return
        self._ekeys.add(key)
        self.edges.append({"src": src, "dst": dst, "rel": rel, "evidence": evidence, "source": source})

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": list(self.nodes.values()), "edges": self.edges}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Graph":
        g = cls()
        for n in d.get("nodes", []):
            g.nodes[n["id"]] = dict(n)
        for e in d.get("edges", []):
            g.edge(e["src"], e["dst"], e["rel"], e.get("evidence", "observed"), e.get("source", ""))
        return g

    def neighborhood(self, center: str, depth: int = 1, kinds: Optional[Iterable[str]] = None,
                     max_nodes: int = 150) -> "Graph":
        """Sous-graphe autour d'un nœud (dans les deux sens), limité en taille."""
        allowed = set(kinds) if kinds else None
        adj: Dict[str, List[Dict[str, Any]]] = {}
        for e in self.edges:
            adj.setdefault(e["src"], []).append(e)
            adj.setdefault(e["dst"], []).append(e)
        keep = {center}
        q = deque([(center, 0)])
        while q and len(keep) < max_nodes:
            n, d = q.popleft()
            if d >= depth:
                continue
            for e in adj.get(n, []):
                other = e["dst"] if e["src"] == n else e["src"]
                if other in keep:
                    continue
                if allowed and self.nodes.get(other, {}).get("kind") not in allowed:
                    continue
                keep.add(other)
                q.append((other, d + 1))
        g = Graph()
        for n in keep:
            if n in self.nodes:
                g.nodes[n] = dict(self.nodes[n])
        for e in self.edges:
            if e["src"] in keep and e["dst"] in keep:
                g.edge(e["src"], e["dst"], e["rel"], e["evidence"], e["source"])
        return g

    def to_dot(self) -> str:
        shapes = {"service": "box", "executable": "component", "library": "ellipse", "domain": "hexagon",
                  "binder": "diamond", "trigger": "plaintext", "socket": "cds", "hal": "diamond"}
        lines = ["digraph horizonlab {", "  rankdir=LR;", "  node [fontname=Helvetica,fontsize=10];"]
        for n in self.nodes.values():
            lab = n["label"].replace('"', "'")
            lines.append(f'  "{n["id"]}" [label="{lab}", shape={shapes.get(n["kind"], "ellipse")}];')
        for e in self.edges:
            style = "dashed" if e["evidence"] == "hypothesis" else "solid"
            lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{e["rel"]}", style={style}];')
        lines.append("}")
        return "\n".join(lines)

    def stats(self) -> Dict[str, Any]:
        kinds: Dict[str, int] = {}
        for n in self.nodes.values():
            kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
        rels: Dict[str, int] = {}
        for e in self.edges:
            rels[e["rel"]] = rels.get(e["rel"], 0) + 1
        return {"nodes": len(self.nodes), "edges": len(self.edges), "node_kinds": kinds, "edge_kinds": rels}
