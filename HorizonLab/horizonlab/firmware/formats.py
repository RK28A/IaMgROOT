"""Identification et analyse (lecture seule) des formats d'images Android.

Formats pris en charge (en-têtes / métadonnées) :
  * Android sparse image            (magic 0xED26FF3A)
  * ext4                            (superbloc, magic 0xEF53 @1080)
  * EROFS                           (superbloc, magic 0xE0F5E1E2 @1024)
  * boot image v0-v4                ("ANDROID!")
  * vendor_boot v3-v4               ("VNDRBOOT")
  * vbmeta / AVB                    ("AVB0", pied de page "AVBf")
  * super (partitions dynamiques)   (géométrie "gDla", métadonnées "0PLA")
  * DTBO / DTB                      (0xD7B7AB1E / 0xD00DFEED)
  * payload.bin OTA A/B             ("CrAU")
  * ELF, ZIP/APK/APEX, gzip, LZ4, cpio newc

Toutes les fonctions ouvrent les fichiers en mode ``rb`` uniquement.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

SPARSE_MAGIC = 0xED26FF3A
EXT4_MAGIC = 0xEF53
EROFS_MAGIC = 0xE0F5E1E2
LP_GEOMETRY_MAGIC = 0x616C4467
LP_HEADER_MAGIC = 0x414C5030
LP_PARTITION_RESERVED_BYTES = 4096
LP_METADATA_GEOMETRY_SIZE = 4096
DTBO_MAGIC = 0xD7B7AB1E
FDT_MAGIC = 0xD00DFEED


def _read_at(f: BinaryIO, off: int, n: int) -> bytes:
    f.seek(off)
    return f.read(n)


def _cstr(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("utf-8", "replace")


# --------------------------------------------------------------------------- détection
def detect_format(path: Path) -> str:
    """Retourne un identifiant de format (``unknown`` si non reconnu)."""
    path = Path(path)
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            head = f.read(4096 + 64)
            if len(head) >= 4 and struct.unpack_from("<I", head)[0] == SPARSE_MAGIC:
                return "sparse"
            if head[:8] == b"ANDROID!":
                return "boot"
            if head[:8] == b"VNDRBOOT":
                return "vendor_boot"
            if head[:8] == b"BOOTIMG\0" or head[:8] == b"VNDRBOOT":
                return "boot"
            if head[:4] == b"AVB0":
                return "vbmeta"
            if head[:4] == b"CrAU":
                return "payload"
            if head[:4] == b"\x7fELF":
                return "elf"
            if head[:4] == b"PK\x03\x04":
                low = path.name.lower()
                if low.endswith(".apk"):
                    return "apk"
                if low.endswith((".apex", ".capex")):
                    return "apex"
                if low.endswith(".jar"):
                    return "jar"
                return "zip"
            if head[:2] == b"\x1f\x8b":
                return "gzip"
            if head[:4] in (b"\x02\x21\x4c\x18", b"\x04\x22\x4d\x18"):
                return "lz4"
            if head[:6] in (b"070701", b"070702"):
                return "cpio"
            if len(head) >= 4:
                m = struct.unpack_from(">I", head)[0]
                if m == DTBO_MAGIC:
                    return "dtbo"
                if m == FDT_MAGIC:
                    return "dtb"
            if len(head) >= 1024 + 4 and struct.unpack_from("<I", head, 1024)[0] == EROFS_MAGIC:
                return "erofs"
            if len(head) >= 1082 and struct.unpack_from("<H", head, 1080)[0] == EXT4_MAGIC:
                return "ext4"
            if len(head) >= 4100 and struct.unpack_from("<I", head, 4096)[0] == LP_GEOMETRY_MAGIC:
                return "super"
            if len(head) >= 0x3C and head[0x38:0x3C] == b"ARM\x64":
                return "arm64_kernel"
            if size >= 64:
                tail = _read_at(f, size - 64, 64)
                if tail[:4] == b"AVBf":
                    return "avb_footer_image"
    except OSError:
        return "unreadable"
    return "unknown"


# --------------------------------------------------------------------------- sparse
def parse_sparse_header(path: Path) -> Dict[str, Any]:
    with open(path, "rb") as f:
        h = f.read(28)
    (magic, major, minor, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks, total_chunks,
     checksum) = struct.unpack("<IHHHHIIII", h)
    if magic != SPARSE_MAGIC:
        raise ValueError("pas une image sparse")
    return {
        "version": f"{major}.{minor}", "file_hdr_sz": file_hdr_sz, "chunk_hdr_sz": chunk_hdr_sz,
        "block_size": blk_sz, "total_blocks": total_blks, "total_chunks": total_chunks,
        "expanded_size": blk_sz * total_blks, "checksum": checksum,
    }


def unsparse(src: Path, dest: Path) -> Dict[str, Any]:
    """Convertit une image sparse en image brute (implémentation Python, sans simg2img)."""
    info = parse_sparse_header(src)
    bs = info["block_size"]
    counts = {"raw": 0, "fill": 0, "dont_care": 0, "crc32": 0}
    with open(src, "rb") as f, open(dest, "wb") as out:
        f.seek(info["file_hdr_sz"])
        for _ in range(info["total_chunks"]):
            ch = f.read(info["chunk_hdr_sz"])
            ctype, _res, chunk_blocks, total_sz = struct.unpack_from("<HHII", ch)
            data_sz = total_sz - info["chunk_hdr_sz"]
            if ctype == 0xCAC1:  # RAW
                remaining = data_sz
                while remaining:
                    b = f.read(min(remaining, 1 << 20))
                    if not b:
                        raise ValueError("image sparse tronquée")
                    out.write(b)
                    remaining -= len(b)
                counts["raw"] += 1
            elif ctype == 0xCAC2:  # FILL
                fill = f.read(4)
                block = fill * (bs // 4)
                for _ in range(chunk_blocks):
                    out.write(block)
                counts["fill"] += 1
            elif ctype == 0xCAC3:  # DONT CARE
                out.seek(chunk_blocks * bs, 1)
                counts["dont_care"] += 1
            elif ctype == 0xCAC4:  # CRC32
                f.read(4)
                counts["crc32"] += 1
            else:
                raise ValueError(f"type de bloc sparse inconnu 0x{ctype:x}")
        out.truncate(info["expanded_size"])
    info["chunks"] = counts
    return info


# --------------------------------------------------------------------------- ext4 / erofs
EXT4_FEATURES_COMPAT = {0x4: "has_journal", 0x8: "ext_attr", 0x10: "resize_inode", 0x20: "dir_index"}
EXT4_FEATURES_INCOMPAT = {0x2: "filetype", 0x40: "extents", 0x80: "64bit", 0x200: "flex_bg",
                          0x8000: "inline_data", 0x10000: "encrypt", 0x20000: "casefold"}
EXT4_FEATURES_RO = {0x1: "sparse_super", 0x2: "large_file", 0x8: "huge_file", 0x10: "gdt_csum",
                    0x20: "dir_nlink", 0x40: "extra_isize", 0x400: "metadata_csum", 0x2000: "verity"}


def _flags(v: int, table: Dict[int, str]) -> List[str]:
    out = [n for bit, n in table.items() if v & bit]
    rest = v & ~sum(table)
    if rest:
        out.append(f"0x{rest:x}")
    return out


def parse_ext4_superblock(f: BinaryIO, base: int = 0) -> Dict[str, Any]:
    sb = _read_at(f, base + 1024, 1024)
    if struct.unpack_from("<H", sb, 56)[0] != EXT4_MAGIC:
        raise ValueError("superbloc ext4 absent")
    inodes, blocks_lo = struct.unpack_from("<II", sb, 0)
    log_bs = struct.unpack_from("<I", sb, 24)[0]
    compat, incompat, ro = struct.unpack_from("<III", sb, 92)
    blocks_hi = struct.unpack_from("<I", sb, 0x150)[0] if incompat & 0x80 else 0
    bs = 1024 << log_bs
    return {
        "block_size": bs,
        "blocks": blocks_lo | (blocks_hi << 32),
        "size": bs * (blocks_lo | (blocks_hi << 32)),
        "inodes": inodes,
        "uuid": sb[104:120].hex(),
        "volume_name": _cstr(sb[120:136]),
        "last_mounted": _cstr(sb[136:200]),
        "features": {"compat": _flags(compat, EXT4_FEATURES_COMPAT),
                     "incompat": _flags(incompat, EXT4_FEATURES_INCOMPAT),
                     "ro_compat": _flags(ro, EXT4_FEATURES_RO)},
        "mkfs_time": struct.unpack_from("<I", sb, 0x108)[0],
    }


def parse_erofs_superblock(f: BinaryIO, base: int = 0) -> Dict[str, Any]:
    sb = _read_at(f, base + 1024, 128)
    magic, checksum, feature_compat, blkszbits = struct.unpack_from("<IIIB", sb, 0)
    if magic != EROFS_MAGIC:
        raise ValueError("superbloc EROFS absent")
    sb_extslots = sb[13]
    root_nid = struct.unpack_from("<H", sb, 14)[0]
    inos = struct.unpack_from("<Q", sb, 16)[0]
    build_time = struct.unpack_from("<Q", sb, 24)[0]
    blocks = struct.unpack_from("<I", sb, 36)[0]
    feature_incompat = struct.unpack_from("<I", sb, 80)[0]
    return {
        "block_size": 1 << blkszbits, "blocks": blocks, "size": blocks << blkszbits,
        "inodes": inos, "root_nid": root_nid, "build_time": build_time,
        "uuid": sb[48:64].hex(), "volume_name": _cstr(sb[64:80]),
        "feature_compat": feature_compat, "feature_incompat": feature_incompat,
        "extslots": sb_extslots,
    }


# --------------------------------------------------------------------------- boot images
def decode_os_version(v: int) -> Dict[str, Optional[str]]:
    if not v:
        return {"os_version": None, "os_patch_level": None}
    ver = v >> 11
    pl = v & 0x7FF
    a, b, c = (ver >> 14) & 0x7F, (ver >> 7) & 0x7F, ver & 0x7F
    y, m = (pl >> 4) + 2000, pl & 0xF
    return {"os_version": f"{a}.{b}.{c}", "os_patch_level": f"{y:04d}-{m:02d}" if pl else None}


def _align(x: int, a: int) -> int:
    return (x + a - 1) // a * a


def parse_boot_image(path: Path) -> Dict[str, Any]:
    with open(path, "rb") as f:
        h = f.read(4096)
    if h[:8] != b"ANDROID!":
        raise ValueError("pas une image boot Android")
    hv = struct.unpack_from("<I", h, 40)[0]
    info: Dict[str, Any] = {"header_version": hv}
    if hv >= 3:
        kernel_size, ramdisk_size, os_version, header_size = struct.unpack_from("<IIII", h, 8)
        cmdline = _cstr(h[44:44 + 1536])
        page = 4096
        info.update(kernel_size=kernel_size, ramdisk_size=ramdisk_size, header_size=header_size,
                    page_size=page, cmdline=cmdline, name="")
        info["kernel_offset"] = page
        info["ramdisk_offset"] = page + _align(kernel_size, page)
        if hv >= 4:
            info["signature_size"] = struct.unpack_from("<I", h, 44 + 1536)[0]
    else:
        (kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size, second_addr, tags_addr,
         page_size, _hv, os_version) = struct.unpack_from("<IIIIIIIIII", h, 8)
        name = _cstr(h[48:64])
        cmdline = _cstr(h[64:64 + 512]) + _cstr(h[608:608 + 1024])
        info.update(kernel_size=kernel_size, ramdisk_size=ramdisk_size, second_size=second_size,
                    page_size=page_size, cmdline=cmdline, name=name,
                    kernel_addr=hex(kernel_addr), ramdisk_addr=hex(ramdisk_addr))
        info["kernel_offset"] = page_size
        info["ramdisk_offset"] = page_size + _align(kernel_size, page_size)
        if hv >= 1:
            info["recovery_dtbo_size"] = struct.unpack_from("<I", h, 1632)[0]
        if hv >= 2:
            info["dtb_size"] = struct.unpack_from("<I", h, 1648)[0]
    info.update(decode_os_version(os_version))
    return info


def parse_vendor_boot(path: Path) -> Dict[str, Any]:
    with open(path, "rb") as f:
        h = f.read(4096)
    if h[:8] != b"VNDRBOOT":
        raise ValueError("pas une image vendor_boot")
    hv, page_size, kernel_addr, ramdisk_addr, vendor_ramdisk_size = struct.unpack_from("<IIIII", h, 8)
    cmdline = _cstr(h[28:28 + 2048])
    off = 28 + 2048
    tags_addr = struct.unpack_from("<I", h, off)[0]
    name = _cstr(h[off + 4:off + 20])
    header_size, dtb_size = struct.unpack_from("<II", h, off + 20)
    info = {"header_version": hv, "page_size": page_size, "vendor_ramdisk_size": vendor_ramdisk_size,
            "cmdline": cmdline, "name": name, "header_size": header_size, "dtb_size": dtb_size,
            "ramdisk_offset": _align(header_size, page_size)}
    if hv >= 4:
        o = off + 36
        tbl_size, entry_num, entry_size, bootconfig_size = struct.unpack_from("<IIII", h, o)
        info.update(vendor_ramdisk_table_size=tbl_size, vendor_ramdisk_table_entry_num=entry_num,
                    bootconfig_size=bootconfig_size)
    return info


# --------------------------------------------------------------------------- AVB / vbmeta
AVB_ALGORITHMS = {0: "NONE", 1: "SHA256_RSA2048", 2: "SHA256_RSA4096", 3: "SHA256_RSA8192",
                  4: "SHA512_RSA2048", 5: "SHA512_RSA4096", 6: "SHA512_RSA8192"}


def parse_avb_footer(f: BinaryIO, size: int) -> Optional[Dict[str, Any]]:
    tail = _read_at(f, size - 64, 64)
    if tail[:4] != b"AVBf":
        return None
    vmaj, vmin, orig, vb_off, vb_size = struct.unpack_from(">IIQQQ", tail, 4)
    return {"version": f"{vmaj}.{vmin}", "original_image_size": orig, "vbmeta_offset": vb_off,
            "vbmeta_size": vb_size}


def parse_vbmeta_blob(blob: bytes) -> Dict[str, Any]:
    if blob[:4] != b"AVB0":
        raise ValueError("pas de vbmeta (AVB0)")
    (req_maj, req_min, auth_size, aux_size, algo, hash_off, hash_size, sig_off, sig_size,
     pk_off, pk_size, pkm_off, pkm_size, desc_off, desc_size, rollback, flags,
     rollback_loc) = struct.unpack_from(">IIQQIQQQQQQQQQQQII", blob, 4)
    release = _cstr(blob[0x80:0x80 + 47])
    aux = blob[256 + auth_size: 256 + auth_size + aux_size]
    descriptors = _parse_avb_descriptors(aux[desc_off:desc_off + desc_size])
    pubkey = aux[pk_off:pk_off + pk_size]
    import hashlib

    return {
        "required_libavb": f"{req_maj}.{req_min}",
        "algorithm": AVB_ALGORITHMS.get(algo, str(algo)),
        "rollback_index": rollback,
        "rollback_index_location": rollback_loc,
        "flags": flags,
        "flags_decoded": [n for b, n in ((1, "HASHTREE_DISABLED"), (2, "VERIFICATION_DISABLED")) if flags & b],
        "release_string": release,
        "public_key_sha1": hashlib.sha1(pubkey).hexdigest() if pubkey else None,
        "public_key_sha256": hashlib.sha256(pubkey).hexdigest() if pubkey else None,
        "descriptors": descriptors,
    }


def _parse_avb_descriptors(data: bytes) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    o = 0
    while o + 16 <= len(data):
        tag, nbytes = struct.unpack_from(">QQ", data, o)
        body = data[o + 16:o + 16 + nbytes]
        d: Dict[str, Any] = {"tag": tag}
        try:
            if tag == 0:  # property
                kl, vl = struct.unpack_from(">QQ", body, 0)
                d.update(type="property", key=body[16:16 + kl].decode("utf-8", "replace"),
                         value=body[17 + kl:17 + kl + vl].decode("utf-8", "replace"))
            elif tag == 1:  # hashtree
                (dmv, img_size, tree_off, tree_size, dbs, hbs, fec_roots, fec_off, fec_size) = \
                    struct.unpack_from(">IQQQIIIQQ", body, 0)
                algo = _cstr(body[60:92])
                pnl, sl, rdl, fl = struct.unpack_from(">IIII", body, 92)
                p = 92 + 16 + 60
                name = body[p:p + pnl].decode("utf-8", "replace")
                salt = body[p + pnl:p + pnl + sl].hex()
                root = body[p + pnl + sl:p + pnl + sl + rdl].hex()
                d.update(type="hashtree", partition=name, image_size=img_size, hash_algorithm=algo,
                         dm_verity_version=dmv, data_block_size=dbs, fec_num_roots=fec_roots,
                         salt=salt, root_digest=root, flags=fl)
            elif tag == 2:  # hash
                img_size = struct.unpack_from(">Q", body, 0)[0]
                algo = _cstr(body[8:40])
                pnl, sl, dl, fl = struct.unpack_from(">IIII", body, 40)
                p = 40 + 16 + 60
                d.update(type="hash", partition=body[p:p + pnl].decode("utf-8", "replace"),
                         image_size=img_size, hash_algorithm=algo,
                         salt=body[p + pnl:p + pnl + sl].hex(),
                         digest=body[p + pnl + sl:p + pnl + sl + dl].hex(), flags=fl)
            elif tag == 3:  # kernel cmdline
                fl, ln = struct.unpack_from(">II", body, 0)
                d.update(type="kernel_cmdline", flags=fl, cmdline=body[8:8 + ln].decode("utf-8", "replace"))
            elif tag == 4:  # chain partition
                loc, pnl, pkl = struct.unpack_from(">III", body, 0)
                p = 12 + 4 + 60
                d.update(type="chain_partition", rollback_index_location=loc,
                         partition=body[p:p + pnl].decode("utf-8", "replace"))
            else:
                d["type"] = "unknown"
        except struct.error:
            d["type"] = "truncated"
        out.append(d)
        o += 16 + nbytes
    return out


def parse_vbmeta(path: Path) -> Dict[str, Any]:
    """vbmeta autonome ou image munie d'un pied de page AVB."""
    path = Path(path)
    size = path.stat().st_size
    with open(path, "rb") as f:
        head = f.read(4)
        if head == b"AVB0":
            f.seek(0)
            hdr = f.read(256)
            auth, aux = struct.unpack_from(">QQ", hdr, 12)
            f.seek(0)
            res = parse_vbmeta_blob(f.read(256 + auth + aux))
            res["footer"] = None
            return res
        footer = parse_avb_footer(f, size)
        if not footer:
            raise ValueError("ni vbmeta ni pied de page AVB")
        blob = _read_at(f, footer["vbmeta_offset"], footer["vbmeta_size"])
        res = parse_vbmeta_blob(blob)
        res["footer"] = footer
        return res


# --------------------------------------------------------------------------- super / LP metadata
LP_ATTRS = {0x1: "readonly", 0x2: "slot_suffixed", 0x4: "updated", 0x8: "disabled"}


def parse_super(path: Path, slot: int = 0) -> Dict[str, Any]:
    with open(path, "rb") as f:
        geo = _read_at(f, LP_PARTITION_RESERVED_BYTES, 52)
        magic, struct_size = struct.unpack_from("<II", geo, 0)
        if magic != LP_GEOMETRY_MAGIC:
            raise ValueError("géométrie LP absente")
        metadata_max_size, slot_count, logical_block_size = struct.unpack_from("<III", geo, 40)
        hdr_off = LP_PARTITION_RESERVED_BYTES + 2 * LP_METADATA_GEOMETRY_SIZE + slot * metadata_max_size
        hdr = _read_at(f, hdr_off, 256)
        (hmagic, major, minor, header_size) = struct.unpack_from("<IHHI", hdr, 0)
        if hmagic != LP_HEADER_MAGIC:
            raise ValueError("en-tête de métadonnées LP absent")
        tables_size = struct.unpack_from("<I", hdr, 44)[0]

        def desc(o):
            return struct.unpack_from("<III", hdr, o)

        parts_d, ext_d, grp_d, bdev_d = desc(80), desc(92), desc(104), desc(116)
        tables = _read_at(f, hdr_off + header_size, tables_size)

    def entries(d):
        off, num, esz = d
        return [tables[off + i * esz: off + (i + 1) * esz] for i in range(num)]

    extents = []
    for e in entries(ext_d):
        nsec, ttype, tdata, tsrc = struct.unpack_from("<QIQI", e, 0)
        extents.append({"num_sectors": nsec, "target_type": "linear" if ttype == 0 else "zero",
                        "target_data": tdata, "target_source": tsrc})
    groups = []
    for g in entries(grp_d):
        groups.append({"name": _cstr(g[:36]), "flags": struct.unpack_from("<I", g, 36)[0],
                       "maximum_size": struct.unpack_from("<Q", g, 40)[0]})
    bdevs = []
    for b in entries(bdev_d):
        fls, align, align_off, size = struct.unpack_from("<QIIQ", b, 0)
        bdevs.append({"first_logical_sector": fls, "alignment": align, "size": size,
                      "partition_name": _cstr(b[24:60])})
    parts = []
    for p in entries(parts_d):
        name = _cstr(p[:36])
        attrs, first, num, gidx = struct.unpack_from("<IIII", p, 36)
        exts = extents[first:first + num]
        parts.append({
            "name": name, "attributes": [n for b, n in LP_ATTRS.items() if attrs & b],
            "group": groups[gidx]["name"] if gidx < len(groups) else gidx,
            "size": sum(e["num_sectors"] for e in exts) * 512, "extents": exts,
        })
    return {"metadata_version": f"{major}.{minor}", "metadata_max_size": metadata_max_size,
            "slot_count": slot_count, "logical_block_size": logical_block_size,
            "partitions": parts, "groups": groups, "block_devices": bdevs}


def extract_super_partition(path: Path, part: Dict[str, Any], dest: Path) -> int:
    """Recopie une partition logique (extents linéaires) vers ``dest``."""
    written = 0
    with open(path, "rb") as f, open(dest, "wb") as out:
        for e in part["extents"]:
            n = e["num_sectors"] * 512
            if e["target_type"] == "zero":
                out.seek(n, 1)
            else:
                f.seek(e["target_data"] * 512)
                remaining = n
                while remaining:
                    b = f.read(min(remaining, 1 << 20))
                    if not b:
                        break
                    out.write(b)
                    remaining -= len(b)
            written += n
        out.truncate(written)
    return written


# --------------------------------------------------------------------------- DTBO
def parse_dtbo(path: Path) -> Dict[str, Any]:
    with open(path, "rb") as f:
        h = f.read(32)
        magic, total, hsize, esize, count, eoff, page, version = struct.unpack(">IIIIIIII", h)
        if magic != DTBO_MAGIC:
            raise ValueError("pas une table DTBO")
        entries = []
        for i in range(count):
            e = _read_at(f, eoff + i * esize, 32)
            sz, off, ident, rev = struct.unpack_from(">IIII", e, 0)
            entries.append({"size": sz, "offset": off, "id": hex(ident), "rev": hex(rev)})
    return {"total_size": total, "version": version, "page_size": page, "entries": entries}


# --------------------------------------------------------------------------- payload.bin
def _pb_varint(buf: bytes, i: int) -> Tuple[int, int]:
    shift = res = 0
    while True:
        b = buf[i]
        i += 1
        res |= (b & 0x7F) << shift
        if not b & 0x80:
            return res, i
        shift += 7


def pb_decode(buf: bytes) -> Dict[int, List[Any]]:
    """Décodeur protobuf minimal : {numéro_de_champ: [valeurs]} (bytes pour type 2)."""
    out: Dict[int, List[Any]] = {}
    i = 0
    while i < len(buf):
        key, i = _pb_varint(buf, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _pb_varint(buf, i)
        elif wt == 1:
            v = struct.unpack_from("<Q", buf, i)[0]
            i += 8
        elif wt == 2:
            ln, i = _pb_varint(buf, i)
            v = buf[i:i + ln]
            i += ln
        elif wt == 5:
            v = struct.unpack_from("<I", buf, i)[0]
            i += 4
        else:
            raise ValueError(f"type protobuf non géré {wt}")
        out.setdefault(fn, []).append(v)
    return out


OTA_OP_TYPES = {0: "REPLACE", 1: "REPLACE_BZ", 2: "MOVE", 3: "BSDIFF", 4: "SOURCE_COPY",
                5: "SOURCE_BSDIFF", 6: "ZERO", 7: "DISCARD", 8: "REPLACE_XZ", 9: "PUFFDIFF",
                10: "BROTLI_BSDIFF", 11: "ZUCCHINI", 12: "LZ4DIFF_BSDIFF", 13: "LZ4DIFF_PUFFDIFF",
                14: "REPLACE_ZSTD"}


def parse_payload(path: Path) -> Dict[str, Any]:
    with open(path, "rb") as f:
        h = f.read(24)
        if h[:4] != b"CrAU":
            raise ValueError("pas un payload.bin")
        version, manifest_size = struct.unpack_from(">QQ", h, 4)
        sig_size = struct.unpack_from(">I", h, 20)[0] if version >= 2 else 0
        hdr_len = 24 if version >= 2 else 20
        f.seek(hdr_len)
        manifest = f.read(manifest_size)
    m = pb_decode(manifest)
    parts = []
    for raw in m.get(13, []):
        p = pb_decode(raw)
        name = p.get(1, [b""])[0].decode()
        info = pb_decode(p[7][0]) if 7 in p else {}
        ops = [pb_decode(o) for o in p.get(8, [])]
        op_types: Dict[str, int] = {}
        for o in ops:
            t = OTA_OP_TYPES.get(o.get(1, [0])[0], "?")
            op_types[t] = op_types.get(t, 0) + 1
        parts.append({"name": name, "size": info.get(1, [None])[0],
                      "sha256": info.get(2, [b""])[0].hex() if 2 in info else None,
                      "operations": len(ops), "operation_types": op_types,
                      "delta": 6 in p})
    return {"version": version, "manifest_size": manifest_size, "metadata_signature_size": sig_size,
            "data_offset": hdr_len + manifest_size + sig_size,
            "block_size": m.get(3, [4096])[0], "minor_version": m.get(12, [None])[0],
            "max_timestamp": m.get(14, [None])[0], "partitions": parts,
            "full_ota": all(not p["delta"] for p in parts)}


def extract_payload_partition(path: Path, name: str, dest: Path) -> Dict[str, Any]:
    """Extraction d'une partition d'un OTA *complet* (REPLACE / REPLACE_BZ / REPLACE_XZ / ZERO)."""
    import bz2
    import hashlib
    import lzma

    meta = parse_payload(path)
    with open(path, "rb") as f:
        f.seek(24 if meta["version"] >= 2 else 20)
        m = pb_decode(f.read(meta["manifest_size"]))
        bs = meta["block_size"]
        for raw in m.get(13, []):
            p = pb_decode(raw)
            if p.get(1, [b""])[0].decode() != name:
                continue
            unsupported = set()
            with open(dest, "wb") as out:
                for o in (pb_decode(x) for x in p.get(8, [])):
                    t = o.get(1, [0])[0]
                    dsts = [pb_decode(e) for e in o.get(6, [])]
                    if t in (6, 7):  # ZERO / DISCARD
                        for e in dsts:
                            out.seek(e.get(1, [0])[0] * bs)
                            out.write(b"\0" * (e.get(2, [0])[0] * bs))
                        continue
                    if t not in (0, 1, 8):
                        unsupported.add(OTA_OP_TYPES.get(t, str(t)))
                        continue
                    f.seek(meta["data_offset"] + o.get(2, [0])[0])
                    data = f.read(o.get(3, [0])[0])
                    if t == 1:
                        data = bz2.decompress(data)
                    elif t == 8:
                        data = lzma.decompress(data)
                    pos = 0
                    for e in dsts:
                        n = e.get(2, [0])[0] * bs
                        out.seek(e.get(1, [0])[0] * bs)
                        out.write(data[pos:pos + n])
                        pos += n
            result = {"partition": name, "unsupported_operations": sorted(unsupported)}
            info = pb_decode(p[7][0]) if 7 in p else {}
            if 2 in info and not unsupported:
                size = info.get(1, [0])[0]
                with open(dest, "r+b") as out:
                    out.truncate(size)
                h = hashlib.sha256()
                with open(dest, "rb") as r:
                    for chunk in iter(lambda: r.read(1 << 20), b""):
                        h.update(chunk)
                result["sha256_ok"] = h.hexdigest() == info[2][0].hex()
            return result
    raise KeyError(f"partition {name} absente du payload")


# --------------------------------------------------------------------------- cpio newc (ramdisk)
def iter_cpio(data: bytes):
    """Itère (nom, mode, contenu) sur une archive cpio newc."""
    o = 0
    while o + 110 <= len(data):
        if data[o:o + 6] not in (b"070701", b"070702"):
            break
        fields = [int(data[o + 6 + i * 8: o + 14 + i * 8], 16) for i in range(13)]
        mode, filesize, namesize = fields[1], fields[6], fields[11]
        name = data[o + 110:o + 110 + namesize - 1].decode("utf-8", "replace")
        o = _align(o + 110 + namesize, 4)
        content = data[o:o + filesize]
        o = _align(o + filesize, 4)
        if name == "TRAILER!!!":
            break
        yield name, mode, content


def decompress_any(data: bytes) -> Tuple[bytes, str]:
    """Décompresse gzip / LZ4 (legacy via l'outil lz4) / xz ; renvoie (données, méthode)."""
    import gzip
    import lzma
    import zlib

    if data[:2] == b"\x1f\x8b":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        return d.decompress(data), "gzip"
    if data[:6] == b"\xfd7zXZ\x00":
        return lzma.decompress(data), "xz"
    if data[:4] in (b"\x02\x21\x4c\x18", b"\x04\x22\x4d\x18"):
        import subprocess

        from horizonlab.core.tools import which

        lz4 = which("lz4")
        if not lz4:
            raise RuntimeError("décompression LZ4 : outil 'lz4' introuvable")
        p = subprocess.run([lz4, "-d", "-c"], input=data, capture_output=True, timeout=120)
        if p.returncode != 0 and not p.stdout:
            raise RuntimeError(f"lz4 : {p.stderr.decode('utf-8', 'replace').strip()}")
        return p.stdout, "lz4"
    del gzip
    return data, "none"
