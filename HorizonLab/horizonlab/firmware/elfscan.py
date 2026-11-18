"""Analyse statique des exécutables ELF (pyelftools ; Capstone optionnel)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from elftools.common.exceptions import ELFError
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection, SymbolTableSection
    HAVE_ELFTOOLS = True
except ImportError:  # pragma: no cover
    HAVE_ELFTOOLS = False

try:
    import capstone  # type: ignore
    HAVE_CAPSTONE = True
except ImportError:  # pragma: no cover
    HAVE_CAPSTONE = False

ELF_TYPES = {"ET_EXEC": "executable", "ET_DYN": "shared", "ET_REL": "relocatable", "ET_CORE": "core"}
FORTIFY_SUFFIX = "_chk"


def is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def analyze_elf(path: Path, disasm_entry: int = 0) -> Dict[str, Any]:
    """Métadonnées ELF + indicateurs de durcissement. ``disasm_entry`` : nb d'instructions."""
    if not HAVE_ELFTOOLS:
        raise RuntimeError("pyelftools n'est pas installé (pip install pyelftools)")
    path = Path(path)
    out: Dict[str, Any] = {}
    with open(path, "rb") as f:
        try:
            elf = ELFFile(f)
        except ELFError as e:
            return {"error": f"ELF invalide : {e}"}
        out["class"] = elf.elfclass
        out["machine"] = elf["e_machine"]
        out["type"] = ELF_TYPES.get(elf["e_type"], elf["e_type"])
        out["entry"] = hex(elf["e_entry"])
        interp = None
        relro = False
        nx = True
        has_stack_seg = False
        segs = []
        for seg in elf.iter_segments():
            t = seg["p_type"]
            if t == "PT_INTERP":
                interp = seg.get_interp_name()
            elif t == "PT_GNU_RELRO":
                relro = True
            elif t == "PT_GNU_STACK":
                has_stack_seg = True
                nx = not bool(seg["p_flags"] & 1)
            segs.append(t)
        out["interpreter"] = interp
        needed: List[str] = []
        soname = rpath = runpath = None
        bind_now = False
        flags1 = 0
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    tt = tag.entry.d_tag
                    if tt == "DT_NEEDED":
                        needed.append(tag.needed)
                    elif tt == "DT_SONAME":
                        soname = tag.soname
                    elif tt == "DT_RPATH":
                        rpath = tag.rpath
                    elif tt == "DT_RUNPATH":
                        runpath = tag.runpath
                    elif tt == "DT_BIND_NOW":
                        bind_now = True
                    elif tt == "DT_FLAGS" and tag.entry.d_val & 0x8:
                        bind_now = True
                    elif tt == "DT_FLAGS_1":
                        flags1 = tag.entry.d_val
                        if flags1 & 0x1:
                            bind_now = True
        out.update(needed=needed, soname=soname, rpath=rpath, runpath=runpath)
        imports: List[str] = []
        exports = 0
        dynsym = elf.get_section_by_name(".dynsym")
        if isinstance(dynsym, SymbolTableSection):
            for s in dynsym.iter_symbols():
                if not s.name:
                    continue
                if s["st_shndx"] == "SHN_UNDEF":
                    imports.append(s.name)
                elif s["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK"):
                    exports += 1
        out["imports_count"] = len(imports)
        out["exports_count"] = exports
        out["has_symtab"] = elf.get_section_by_name(".symtab") is not None
        build_id = None
        for sec in elf.iter_sections():
            if isinstance(sec, NoteSection):
                for n in sec.iter_notes():
                    if n["n_type"] == "NT_GNU_BUILD_ID":
                        build_id = n["n_desc"]
        out["build_id"] = build_id
        is_library = out["type"] == "shared" and interp is None and not (flags1 & 0x08000000)
        pie = out["type"] == "shared" and (interp is not None or bool(flags1 & 0x08000000))
        out["is_library"] = is_library
        out["hardening"] = {
            # PIE n'a de sens que pour un exécutable ; une bibliothèque est toujours PIC.
            "pie": None if is_library or out["type"] == "relocatable" else bool(pie),
            "nx": nx if has_stack_seg else None,
            "relro": ("full" if bind_now else "partial") if relro else "none",
            "stack_protector": any(i in ("__stack_chk_fail", "__stack_chk_guard") for i in imports),
            "fortify": any(i.startswith("__") and i.endswith(FORTIFY_SUFFIX) for i in imports),
            "cfi": any("__cfi" in i for i in imports),
            "shadow_call_stack": None,
        }
        sections = {s.name: s["sh_size"] for s in elf.iter_sections() if s.name}
        out["section_count"] = len(sections)
        out["has_relr"] = ".relr.dyn" in sections
        out["has_gnu_debugdata"] = ".gnu_debugdata" in sections  # mini-debuginfo Android
        out["notable_imports"] = sorted(i for i in imports if i in NOTABLE_IMPORTS)
        if disasm_entry and HAVE_CAPSTONE and elf["e_machine"] == "EM_AARCH64" and elf["e_entry"]:
            out["entry_disasm"] = _disasm(elf, elf["e_entry"], disasm_entry)
    return out


# Imports dont la présence est utile pour cartographier les fonctions d'un binaire.
NOTABLE_IMPORTS = {
    "ioctl", "mmap", "open", "openat", "socket", "connect", "bind", "dlopen", "execve", "fork",
    "prctl", "setuid", "setgid", "capset", "syscall", "ptrace", "io_uring_setup",
    "AServiceManager_addService", "AServiceManager_getService", "AIBinder_Class_define",
    "_ZN7android21defaultServiceManagerEv", "__system_property_get", "__system_property_set",
    "selinux_android_restorecon", "getcon", "setcon", "minijail_new", "android_log_write",
    "__android_log_print", "vkCreateInstance", "eglGetDisplay", "ANativeWindow_fromSurface",
}


def _disasm(elf, vaddr: int, count: int) -> List[str]:
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD" and seg["p_vaddr"] <= vaddr < seg["p_vaddr"] + seg["p_filesz"]:
            data = seg.data()[vaddr - seg["p_vaddr"]: vaddr - seg["p_vaddr"] + count * 4]
            md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            return [f"{i.address:#x}: {i.mnemonic} {i.op_str}".strip() for i in md.disasm(data, vaddr)][:count]
    return []


def disassemble(path: Path, symbol: Optional[str] = None, vaddr: Optional[int] = None,
                count: int = 32) -> Dict[str, Any]:
    """Désassemblage ARM64 ponctuel (d'un symbole exporté ou d'une adresse)."""
    if not HAVE_CAPSTONE:
        return {"error": "capstone non installé (pip install capstone)"}
    with open(path, "rb") as f:
        elf = ELFFile(f)
        if symbol:
            for name in (".dynsym", ".symtab"):
                sec = elf.get_section_by_name(name)
                if isinstance(sec, SymbolTableSection):
                    syms = sec.get_symbol_by_name(symbol)
                    if syms:
                        vaddr = syms[0]["st_value"]
                        break
        if vaddr is None:
            return {"error": "symbole introuvable"}
        return {"address": hex(vaddr), "instructions": _disasm(elf, vaddr, count)}
