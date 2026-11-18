"""Générateur d'ELF64 AArch64 minimaux (en Python pur) pour les jeux d'essai.

Les fichiers produits sont des ELF valides lisibles par pyelftools / readelf : en-têtes,
segments (INTERP, LOAD, DYNAMIC, GNU_STACK, GNU_RELRO, NOTE), sections (.interp, .dynstr,
.dynsym, .text, .dynamic, .note.gnu.build-id, .shstrtab). Ils ne sont PAS destinés à être
exécutés (le code se limite à « mov x0,#0 ; ret »).
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import List, Optional, Sequence

EM_AARCH64 = 183
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_PHDR = 1, 2, 3, 4, 6
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
DT = {"NULL": 0, "NEEDED": 1, "STRTAB": 5, "SYMTAB": 6, "STRSZ": 10, "SYMENT": 11, "SONAME": 14,
      "FLAGS": 30, "FLAGS_1": 0x6FFFFFFB}


def _pad(b: bytearray, align: int) -> None:
    while len(b) % align:
        b.append(0)


def make_elf(path: Path, needed: Sequence[str] = (), soname: Optional[str] = None,
             interp: Optional[str] = "/system/bin/linker64", imports: Sequence[str] = (),
             exports: Sequence[str] = (), relro: bool = True, bind_now: bool = True,
             nx_stack: bool = True, extra: bytes = b"") -> Path:
    path = Path(path)
    body = bytearray(b"\0" * 64)  # en-tête ELF rempli à la fin
    nph = 5 + (1 if interp else 0) + (1 if relro else 0)
    phoff = 64
    body += b"\0" * (56 * nph)

    def add(data: bytes, align: int = 8) -> int:
        _pad(body, align)
        off = len(body)
        body.extend(data)
        return off

    interp_off = add(interp.encode() + b"\0", 1) if interp else 0
    strtab = bytearray(b"\0")
    name_off = {}

    def s(x: str) -> int:
        if x not in name_off:
            name_off[x] = len(strtab)
            strtab.extend(x.encode() + b"\0")
        return name_off[x]

    for n in needed:
        s(n)
    if soname:
        s(soname)
    for n in list(imports) + list(exports):
        s(n)
    code = struct.pack("<II", 0xD2800000, 0xD65F03C0) + extra
    # .dynsym : symbole nul + imports (non définis) + exports (définis dans .text)
    dynsym_entries = [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]
    text_shndx = 4  # index de section de .text (cf. table plus bas)
    for n in imports:
        dynsym_entries.append(struct.pack("<IBBHQQ", s(n), 0x12, 0, 0, 0, 0))
    dynstr_off = add(bytes(strtab), 1)
    dynsym_off_placeholder = len(body)
    _pad(body, 8)
    dynsym_off = len(body)
    body.extend(b"\0" * (24 * (1 + len(imports) + len(exports))))
    text_off = add(code, 16)
    for n in exports:
        dynsym_entries.append(struct.pack("<IBBHQQ", s(n), 0x12, 0, text_shndx, text_off, 8))
    body[dynsym_off:dynsym_off + 24 * len(dynsym_entries)] = b"".join(dynsym_entries)
    del dynsym_off_placeholder
    dyn = []
    for n in needed:
        dyn.append((DT["NEEDED"], s(n)))
    if soname:
        dyn.append((DT["SONAME"], s(soname)))
    dyn += [(DT["STRTAB"], dynstr_off), (DT["SYMTAB"], dynsym_off), (DT["STRSZ"], len(strtab)),
            (DT["SYMENT"], 24)]
    if bind_now:
        dyn.append((DT["FLAGS"], 0x8))
    if interp:
        dyn.append((DT["FLAGS_1"], 0x08000000 | (0x1 if bind_now else 0)))
    dyn.append((DT["NULL"], 0))
    dynamic_off = add(b"".join(struct.pack("<qQ", t, v) for t, v in dyn), 8)
    bid = hashlib.sha1(path.name.encode() + b"".join(n.encode() for n in needed)).digest()
    note = struct.pack("<III", 4, len(bid), 3) + b"GNU\0" + bid
    note_off = add(note, 4)
    shstr = bytearray(b"\0")
    sh_names = {}
    for n in (".interp", ".dynstr", ".dynsym", ".text", ".dynamic", ".note.gnu.build-id", ".shstrtab"):
        sh_names[n] = len(shstr)
        shstr.extend(n.encode() + b"\0")
    shstr_off = add(bytes(shstr), 1)
    _pad(body, 8)
    shoff = len(body)
    sections = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]

    def sh(name, typ, flags, off, size, link=0, info=0, align=1, entsize=0):
        sections.append(struct.pack("<IIQQQQIIQQ", sh_names[name], typ, flags, off, off, size, link, info,
                                    align, entsize))

    # ordre : 1 .interp, 2 .dynstr, 3 .dynsym, 4 .text, 5 .dynamic, 6 note, 7 .shstrtab
    sh(".interp", 1, 2, interp_off, len(interp) + 1 if interp else 0)
    sh(".dynstr", 3, 2, dynstr_off, len(strtab))
    sh(".dynsym", 11, 2, dynsym_off, 24 * len(dynsym_entries), link=2, info=1, align=8, entsize=24)
    sh(".text", 1, 6, text_off, len(code), align=16)
    sh(".dynamic", 6, 3, dynamic_off, 16 * len(dyn), link=2, align=8, entsize=16)
    sh(".note.gnu.build-id", 7, 2, note_off, len(note), align=4)
    sections.append(struct.pack("<IIQQQQIIQQ", sh_names[".shstrtab"], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0))
    body.extend(b"".join(sections))
    total = len(body)
    ph = []
    ph.append(struct.pack("<IIQQQQQQ", PT_PHDR, 4, phoff, phoff, phoff, 56 * nph, 56 * nph, 8))
    if interp:
        ph.append(struct.pack("<IIQQQQQQ", PT_INTERP, 4, interp_off, interp_off, interp_off,
                              len(interp) + 1, len(interp) + 1, 1))
    ph.append(struct.pack("<IIQQQQQQ", PT_LOAD, 5, 0, 0, 0, total, total, 0x1000))
    ph.append(struct.pack("<IIQQQQQQ", PT_DYNAMIC, 6, dynamic_off, dynamic_off, dynamic_off,
                          16 * len(dyn), 16 * len(dyn), 8))
    ph.append(struct.pack("<IIQQQQQQ", PT_NOTE, 4, note_off, note_off, note_off, len(note), len(note), 4))
    ph.append(struct.pack("<IIQQQQQQ", PT_GNU_STACK, 6 if nx_stack else 7, 0, 0, 0, 0, 0, 16))
    if relro:
        ph.append(struct.pack("<IIQQQQQQ", PT_GNU_RELRO, 4, dynamic_off, dynamic_off, dynamic_off,
                              16 * len(dyn), 16 * len(dyn), 1))
    body[phoff:phoff + 56 * nph] = b"".join(ph)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    hdr = ident + struct.pack("<HHIQQQIHHHHHH", 3, EM_AARCH64, 1, text_off, phoff, shoff, 0, 64, 56, nph,
                              64, len(sections), 7)
    body[0:64] = hdr
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(body))
    return path


def make_library(path: Path, soname: str, needed: Sequence[str] = (), exports: Sequence[str] = ("hl_fn",),
                 imports: Sequence[str] = (), **kw) -> Path:
    return make_elf(path, needed=needed, soname=soname, interp=None, exports=exports, imports=imports, **kw)


def needed_of(path: Path) -> List[str]:
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile

    with open(path, "rb") as f:
        e = ELFFile(f)
        for sec in e.iter_sections():
            if isinstance(sec, DynamicSection):
                return [t.needed for t in sec.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
    return []
