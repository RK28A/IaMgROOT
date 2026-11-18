"""Jeux d'essai SYNTHÉTIQUES imitant la structure d'un firmware Android de casque.

IMPORTANT : ces arborescences ne contiennent AUCUN fichier Meta. Elles sont générées de
toutes pièces pour tester HorizonLab (noms de code publics « hollywood » / « eureka »
utilisés uniquement pour exercer l'identification). Toutes les propriétés portent
``ro.build.description=HORIZONLAB SYNTHETIC FIXTURE``.
"""
from __future__ import annotations

import gzip
import io
import shutil
import struct
from pathlib import Path
from typing import Dict, Optional

from horizonlab.testing.elfgen import make_elf, make_library

DATA = Path(__file__).parent / "data"
FIXTURE_MARK = "HORIZONLAB SYNTHETIC FIXTURE - NOT META FIRMWARE"

VARIANTS: Dict[str, Dict] = {
    "q2": {
        "device": "hollywood", "model": "Quest 2", "platform": "kona", "release": "12", "sdk": "32",
        "patch": "2024-01-05", "kernel": "4.19.157-hlfixture", "sar": False, "boot_header": 2,
        "extra_services": [], "permissive": ["hl_debug"], "full_relro": False,
        "build_id": "HLFIX.Q2.001",
    },
    "q3": {
        "device": "eureka", "model": "Quest 3", "platform": "hlplatform3", "release": "14", "sdk": "34",
        "patch": "2025-06-05", "kernel": "5.10.209-hlfixture", "sar": True, "boot_header": 4,
        "extra_services": ["hl_scene"], "permissive": [], "full_relro": True,
        "build_id": "HLFIX.Q3.001",
    },
}


def _w(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def fake_kernel(version: str, compressed: bool = True) -> bytes:
    """Noyau factice : en-tête Image ARM64 + bannière + IKCONFIG gzip ; compressé en gzip."""
    hdr = bytearray(64)
    struct.pack_into("<IIQQQ", hdr, 0, 0x14000000, 0, 0x80000, 0x200000, 0xA)
    hdr[0x38:0x3C] = b"ARM\x64"
    banner = (f"Linux version {version} (builder@horizonlab) (Android clang version 14.0.0, LLD 14.0.0)"
              f" #1 SMP PREEMPT Mon Jan 1 00:00:00 UTC 2024\n").encode()
    cfg = "\n".join([
        "CONFIG_SECURITY_SELINUX=y", "# CONFIG_SECURITY_SELINUX_DEVELOP is not set", "CONFIG_SECCOMP=y",
        "CONFIG_SECCOMP_FILTER=y", "CONFIG_STACKPROTECTOR_STRONG=y", "CONFIG_DM_VERITY=y",
        "CONFIG_ANDROID_BINDER_IPC=y", "CONFIG_MODULES=y",
        "CONFIG_CFI_CLANG=y" if version.startswith("5.") else "# CONFIG_CFI_CLANG is not set",
        "CONFIG_SHADOW_CALL_STACK=y" if version.startswith("5.") else "# CONFIG_SHADOW_CALL_STACK is not set",
        "CONFIG_IO_URING=y", "# CONFIG_DEVMEM is not set", "CONFIG_QCOM_KGSL=y",
    ]) + "\n"
    ik = b"IKCFG_ST" + gzip.compress(cfg.encode()) + b"IKCFG_ED"
    blob = bytes(hdr) + b"\0" * 64 + banner + b"\0" * 32 + ik + b"\0" * 256
    return gzip.compress(blob) if compressed else blob


def cpio_newc(files: Dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    ino = 1

    def entry(name: str, data: bytes, mode: int):
        nonlocal ino
        nb = name.encode() + b"\0"
        hdr = b"070701" + b"".join(f"{v:08X}".encode() for v in (
            ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nb), 0))
        out.write(hdr + nb)
        out.write(b"\0" * ((4 - (110 + len(nb)) % 4) % 4))
        out.write(data)
        out.write(b"\0" * ((4 - len(data) % 4) % 4))
        ino += 1

    dirs = sorted({str(Path(n).parent) for n in files if str(Path(n).parent) != "."})
    for d in dirs:
        entry(d, b"", 0o040755)
    for n, d in files.items():
        entry(n, d, 0o100644)
    entry("TRAILER!!!", b"", 0)
    return out.getvalue()


def encode_os_version(version: str, patch: str) -> int:
    a, b, c = (int(x) for x in (version.split(".") + ["0", "0"])[:3])
    y, m = int(patch[:4]), int(patch[5:7])
    return (((a << 14) | (b << 7) | c) << 11) | (((y - 2000) << 4) | m)


def make_boot_image(path: Path, kernel: bytes, ramdisk: bytes, header_version: int,
                    os_version: int, cmdline: str = "console=ttyMSM0 androidboot.hardware=hlfixture") -> Path:
    page = 4096 if header_version >= 3 else 2048
    if header_version >= 3:
        h = bytearray(4096)
        h[:8] = b"ANDROID!"
        struct.pack_into("<IIII", h, 8, len(kernel), len(ramdisk), os_version, 1584 if header_version == 4 else 1580)
        struct.pack_into("<I", h, 40, header_version)
        c = cmdline.encode()[:1535]
        h[44:44 + len(c)] = c
        if header_version == 4:
            struct.pack_into("<I", h, 44 + 1536, 0)
    else:
        h = bytearray(page)
        h[:8] = b"ANDROID!"
        struct.pack_into("<IIIIIIIIII", h, 8, len(kernel), 0x8000, len(ramdisk), 0x1000000, 0, 0, 0x100,
                         page, header_version, os_version)
        h[48:48 + 10] = b"hlfixture\0"
        c = cmdline.encode()[:511]
        h[64:64 + len(c)] = c
    out = bytes(h)

    def padded(b: bytes) -> bytes:
        return b + b"\0" * ((page - len(b) % page) % page)

    out += padded(kernel) + padded(ramdisk)
    path.write_bytes(out)
    return path


def make_vbmeta(path: Path, partitions: Dict[str, bytes], release: str = "avbtool 1.2.0",
                rollback: int = 1, flags: int = 0) -> Path:
    """vbmeta NON SIGNÉ (algorithme NONE) avec descripteurs hash + propriété, pour les tests."""
    import hashlib

    descs = b""

    def desc(tag: int, body: bytes) -> bytes:
        body += b"\0" * ((8 - len(body) % 8) % 8)
        return struct.pack(">QQ", tag, len(body)) + body

    k, v = b"com.horizonlab.fixture", b"true"
    descs += desc(0, struct.pack(">QQ", len(k), len(v)) + k + b"\0" + v + b"\0")
    for name, data in partitions.items():
        salt = hashlib.sha256(name.encode()).digest()
        digest = hashlib.sha256(salt + data).digest()
        nb = name.encode()
        body = struct.pack(">Q", len(data)) + b"sha256".ljust(32, b"\0") + \
            struct.pack(">IIII", len(nb), len(salt), len(digest), 0) + b"\0" * 60 + nb + salt + digest
        descs += desc(2, body)
    aux = descs
    aux += b"\0" * ((64 - len(aux) % 64) % 64)
    hdr = bytearray(256)
    hdr[:4] = b"AVB0"
    struct.pack_into(">IIQQIQQQQQQQQQQQII", hdr, 4, 1, 0, 0, len(aux), 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, len(descs), rollback, flags, 0)
    r = release.encode()[:47]
    hdr[0x80:0x80 + len(r)] = r
    path.write_bytes(bytes(hdr) + aux)
    return path


def build_tree(root: Path, variant: str) -> Path:
    """Construit une arborescence « extraite » synthétique (system/, vendor/, ...)."""
    v = VARIANTS[variant]
    root = Path(root)
    if root.exists():
        shutil.rmtree(root)
    sysroot = root / "system" / "system" if v["sar"] else root / "system"
    vendor = root / "vendor"
    _w(sysroot / "build.prop", "\n".join([
        f"# {FIXTURE_MARK}",
        f"ro.build.id={v['build_id']}",
        f"ro.build.display.id={v['build_id']} fixture",
        "ro.build.version.incremental=0001",
        f"ro.build.version.release={v['release']}",
        f"ro.build.version.sdk={v['sdk']}",
        f"ro.build.version.security_patch={v['patch']}",
        "ro.build.type=user", "ro.build.tags=test-keys",
        f"ro.build.description={FIXTURE_MARK}",
        f"ro.build.fingerprint=horizonlab/{v['device']}/{v['device']}:{v['release']}/{v['build_id']}/0001:user/test-keys",
        f"ro.product.system.device={v['device']}",
        "ro.product.system.manufacturer=HorizonLab",
        "ro.treble.enabled=true", "ro.apex.updatable=true", "ro.secure=1", "ro.debuggable=0", "ro.adb.secure=1",
        "persist.sys.dalvik.vm.lib.2=libart.so",
    ]) + "\n")
    _w(vendor / "build.prop", "\n".join([
        f"# {FIXTURE_MARK}",
        f"ro.product.vendor.device={v['device']}", f"ro.product.vendor.model={v['model']}",
        f"ro.product.model={v['model']}", f"ro.product.device={v['device']}",
        f"ro.board.platform={v['platform']}", "ro.hardware=hlfixture",
        f"ro.vendor.build.security_patch={v['patch']}", f"ro.vndk.version={v['sdk']}",
        "ro.product.cpu.abilist=arm64-v8a,armeabi-v7a,armeabi",
    ]) + "\n")
    relro_full = v["full_relro"]
    # --- bibliothèques
    lib = sysroot / "lib64"
    make_library(lib / "libc.so", "libc.so", exports=("malloc", "free", "ioctl"))
    make_library(lib / "liblog.so", "liblog.so", needed=["libc.so"], exports=("__android_log_print",))
    make_library(lib / "libutils.so", "libutils.so", needed=["libc.so", "liblog.so"])
    make_library(lib / "libbinder.so", "libbinder.so", needed=["libc.so", "liblog.so", "libutils.so"],
                 exports=("_ZN7android21defaultServiceManagerEv",), bind_now=relro_full)
    make_library(lib / "libbinder_ndk.so", "libbinder_ndk.so", needed=["libbinder.so"],
                 exports=("AServiceManager_addService",))
    make_library(lib / "libsurfaceflinger.so", "libsurfaceflinger.so",
                 needed=["libbinder.so", "libutils.so", "libgui.so"])  # libgui.so volontairement absente
    if variant == "q2":
        make_library(lib / "libhl_legacy.so", "libhl_legacy.so", needed=["libc.so"])
    make_elf(sysroot / "bin" / "linker64", interp=None, exports=("__dl_main",))
    make_elf(sysroot / "bin" / "servicemanager", needed=["libbinder.so", "libc.so", "liblog.so"],
             imports=("__stack_chk_fail", "ioctl", "selinux_android_restorecon"), bind_now=relro_full)
    make_elf(sysroot / "bin" / "surfaceflinger", needed=["libsurfaceflinger.so", "libbinder.so", "libc.so"],
             imports=("__stack_chk_fail", "eglGetDisplay"))
    make_elf(sysroot / "bin" / "vold", needed=["libbinder.so", "libc.so", "liblog.so"],
             imports=("__stack_chk_fail", "__memcpy_chk", "ioctl", "open"))
    make_elf(sysroot / "bin" / "toybox", needed=["libc.so"], imports=("__stack_chk_fail",))
    vlib = vendor / "lib64"
    make_library(vlib / "libhl_tracking.so", "libhl_tracking.so", needed=["libc.so", "liblog.so"])
    make_elf(vendor / "bin" / "hw" / "vendor.horizonlab.tracking-service",
             needed=["libbinder_ndk.so", "libhl_tracking.so", "libc.so"],
             imports=("AServiceManager_addService", "__stack_chk_fail"))
    make_elf(vendor / "bin" / "hl_thermal", needed=["libc.so", "liblog.so"], imports=("open",),
             nx_stack=variant != "q2")
    if "hl_scene" in v["extra_services"]:
        make_library(vlib / "libhl_scene.so", "libhl_scene.so", needed=["libc.so", "libbinder_ndk.so"])
        make_elf(vendor / "bin" / "hw" / "vendor.horizonlab.scene-service",
                 needed=["libbinder_ndk.so", "libhl_scene.so", "libc.so"], imports=("AServiceManager_addService",))
    # --- init
    _w(sysroot / "etc" / "init" / "hw" / "init.rc", """# fixture init.rc
import /init.environ.rc
import /system/etc/init/hw/init.${ro.hardware}.rc

on early-init
    write /proc/sys/kernel/sysrq 0
    start ueventd

on init
    mkdir /dev/socket 0755 root root
    start servicemanager

on late-init
    trigger early-fs
    trigger fs
    trigger post-fs
    trigger boot

on boot
    class_start hal
    class_start core

on nonencrypted
    class_start main
    class_start late_start

on property:sys.boot_completed=1
    start hl_postboot

service servicemanager /system/bin/servicemanager
    class core animation
    user system
    group system readproc
    critical
    onrestart restart surfaceflinger
    onrestart class_restart main
    task_profiles ServiceCapacityLow
    shutdown critical

service surfaceflinger /system/bin/surfaceflinger
    class core animation
    user system
    group graphics drmrpc readproc
    capabilities SYS_NICE
    onrestart restart --only-if-running zygote
    socket pdx/system/vr/display/client stream 0666 system graphics u:object_r:pdx_display_client_endpoint_socket:s0
    task_profiles HighPerformance

service vold /system/bin/vold --blkid_context=u:r:blkid:s0
    class core
    ioprio be 2
    writepid /dev/cpuset/foreground/tasks
    shutdown critical
    group root reserved_disk

service hl_postboot /system/bin/toybox echo boot
    class main
    oneshot
    disabled
    user nobody
""")
    _w(vendor / "etc" / "init" / "vendor.horizonlab.tracking-service.rc", """
service vendor.hl_tracking /vendor/bin/hw/vendor.horizonlab.tracking-service
    class hal
    user system
    group system camera input
    interface aidl vendor.horizonlab.tracking.ITracking/default
    capabilities SYS_NICE
""")
    _w(vendor / "etc" / "init" / "hl_thermal.rc", """
on post-fs-data
    mkdir /data/vendor/hl_thermal 0770 system system
    start hl_thermal

service hl_thermal /vendor/bin/hl_thermal
    class late_start
    user system
    group system
    seclabel u:r:hl_thermal:s0
""")
    if "hl_scene" in v["extra_services"]:
        _w(vendor / "etc" / "init" / "vendor.horizonlab.scene-service.rc", """
service vendor.hl_scene /vendor/bin/hw/vendor.horizonlab.scene-service
    class hal
    user system
    group system camera
    interface aidl vendor.horizonlab.scene.ISceneUnderstanding/default
""")
    # --- VINTF
    hals = ["""    <hal format="aidl">
        <name>vendor.horizonlab.tracking</name>
        <version>1</version>
        <fqname>ITracking/default</fqname>
    </hal>""", """    <hal format="hidl">
        <name>android.hardware.graphics.composer</name>
        <transport>hwbinder</transport>
        <fqname>@2.4::IComposer/default</fqname>
    </hal>"""]
    if "hl_scene" in v["extra_services"]:
        hals.append("""    <hal format="aidl">
        <name>vendor.horizonlab.scene</name>
        <version>2</version>
        <interface><name>ISceneUnderstanding</name><instance>default</instance></interface>
    </hal>""")
    _w(vendor / "etc" / "vintf" / "manifest.xml",
       f'<manifest version="2.0" type="device" target-level="{6 if variant == "q2" else 8}">\n'
       + "\n".join(hals) + "\n</manifest>\n")
    # --- SELinux
    sel = sysroot / "etc" / "selinux"
    _w(sel / "plat_file_contexts", """/system/bin/servicemanager u:object_r:servicemanager_exec:s0
/system/bin/surfaceflinger u:object_r:surfaceflinger_exec:s0
/system/bin/vold u:object_r:vold_exec:s0
/system/bin/toybox u:object_r:toolbox_exec:s0
/system/lib64(/.*)? u:object_r:system_lib_file:s0
""")
    _w(sel / "plat_service_contexts", """SurfaceFlinger u:object_r:surfaceflinger_service:s0
vold u:object_r:vold_service:s0
manager u:object_r:service_manager_service:s0
* u:object_r:default_android_service:s0
""")
    policy = [
        "(type init)", "(type servicemanager)", "(type servicemanager_exec)", "(type surfaceflinger)",
        "(type surfaceflinger_exec)", "(type vold)", "(type vold_exec)", "(type surfaceflinger_service)",
        "(type vold_service)", "(typeattribute domain)", "(typeattributeset domain (init servicemanager surfaceflinger vold))",
        "(typetransition init servicemanager_exec process servicemanager)",
        "(typetransition init surfaceflinger_exec process surfaceflinger)",
        "(typetransition init vold_exec process vold)",
        "(allow surfaceflinger surfaceflinger_service (service_manager (add find)))",
        "(allow vold vold_service (service_manager (add find)))",
        "(allow surfaceflinger servicemanager (binder (call transfer)))",
        "(allow vold servicemanager (binder (call transfer)))",
        "(allow servicemanager self (capability (setuid setgid)))",
        "(neverallow surfaceflinger vold (binder (call)))",
    ]
    _w(sel / "plat_sepolicy.cil", "; " + FIXTURE_MARK + "\n" + "\n".join(policy) + "\n")
    vsel = vendor / "etc" / "selinux"
    _w(vsel / "vendor_file_contexts", """/vendor/bin/hw/vendor\\.horizonlab\\.tracking-service u:object_r:hal_hl_tracking_default_exec:s0
/vendor/bin/hl_thermal u:object_r:hl_thermal_exec:s0
/vendor/bin/hw/vendor\\.horizonlab\\.scene-service u:object_r:hal_hl_scene_default_exec:s0
""")
    _w(vsel / "vndservice_contexts",
       "vendor.horizonlab.trackingd u:object_r:hl_tracking_vndservice:s0\n")
    _w(vsel / "vendor_service_contexts", "vendor.horizonlab.tracking.ITracking/default u:object_r:hal_hl_tracking_service:s0\n"
       + ("vendor.horizonlab.scene.ISceneUnderstanding/default u:object_r:hal_hl_scene_service:s0\n"
          if "hl_scene" in v["extra_services"] else ""))
    _w(vsel / "vendor_hwservice_contexts", "android.hardware.graphics.composer::IComposer u:object_r:hal_graphics_composer_hwservice:s0\n")
    vpol = [
        "(type hal_hl_tracking_default)", "(type hal_hl_tracking_default_exec)", "(type hl_thermal)",
        "(type hl_thermal_exec)", "(type hal_hl_tracking_service)",
        "(typetransition init hal_hl_tracking_default_exec process hal_hl_tracking_default)",
        "(typetransition init hl_thermal_exec process hl_thermal)",
        "(allow hal_hl_tracking_default hal_hl_tracking_service (service_manager (add find)))",
        "(allow hal_hl_tracking_default servicemanager (binder (call transfer)))",
        "(allow hal_hl_tracking_default video_device (chr_file (read write ioctl open)))",
        "(allow hl_thermal sysfs_thermal (file (read open getattr)))",
    ]
    if "hl_scene" in v["extra_services"]:
        vpol += ["(type hal_hl_scene_default)", "(type hal_hl_scene_default_exec)",
                 "(typetransition init hal_hl_scene_default_exec process hal_hl_scene_default)",
                 "(allow hal_hl_scene_default hal_hl_scene_service (service_manager (add find)))"]
    for d in v["permissive"]:
        vpol += [f"(type {d})", f"(typepermissive {d})"]
    _w(vsel / "vendor_sepolicy.cil", "\n".join(vpol) + "\n")
    _w(vsel / "plat_sepolicy_vers.txt", f"{v['sdk']}.0\n")
    # --- permissions
    _w(sysroot / "etc" / "permissions" / "platform.xml", """<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <permission name="android.permission.INTERNET"><group gid="inet" /></permission>
    <permission name="android.permission.BLUETOOTH_ADMIN"><group gid="net_bt_admin" /></permission>
    <permission name="android.permission.CAMERA"><group gid="camera" /></permission>
    <assign-permission name="android.permission.WAKE_LOCK" uid="media" />
    <split-permission name="android.permission.ACCESS_FINE_LOCATION">
        <new-permission name="android.permission.ACCESS_COARSE_LOCATION" />
    </split-permission>
</permissions>
""")
    _w(sysroot / "etc" / "permissions" / "privapp-permissions-hlfixture.xml", """<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <privapp-permissions package="com.horizonlab.fixture.settings">
        <permission name="android.permission.WRITE_SECURE_SETTINGS" />
        <deny-permission name="android.permission.READ_LOGS" />
    </privapp-permissions>
</permissions>
""")
    _w(vendor / "etc" / "permissions" / "hlfixture.hardware.xml", """<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <feature name="android.hardware.vr.headtracking" version="1" />
    <feature name="android.hardware.vulkan.level" version="1" />
""" + ('    <feature name="com.horizonlab.feature.passthrough_color" />\n' if variant == "q3" else "") +
       "</permissions>\n")
    app = sysroot / "priv-app" / "HLFixtureSettings"
    app.mkdir(parents=True, exist_ok=True)
    shutil.copy(DATA / "hl_fixture_settings.apk", app / "HLFixtureSettings.apk")
    # --- linker / divers
    _w(sysroot / "etc" / "public.libraries.txt", "libc.so\nliblog.so\nlibbinder_ndk.so\n")
    _w(sysroot / "etc" / "seccomp_policy" / "hl_fixture.policy",
       "read: 1\nwrite: 1\nioctl: arg1 == 0x1234\n")
    _w(vendor / "etc" / "fstab.hlfixture",
       "system /system ext4 ro,barrier=1 wait,slotselect,avb=vbmeta_system,logical,first_stage_mount\n"
       "/dev/block/by-name/userdata /data f2fs noatime latemount,wait,check,fileencryption=aes-256-xts\n")
    # --- noyau et module
    kdir = root / "boot"
    kdir.mkdir(parents=True, exist_ok=True)
    (kdir / "kernel").write_bytes(fake_kernel(v["kernel"]))
    ko = vendor / "lib" / "modules" / "hl_fixture.ko"
    ko.parent.mkdir(parents=True, exist_ok=True)
    ko.write_bytes(b"\x7fELF" + b"\0" * 60 + f"vermagic={v['kernel']} SMP preempt mod_unload aarch64\0".encode())
    _w(root / "HORIZONLAB_FIXTURE.txt", FIXTURE_MARK + "\n")
    return root


def build_images(tree: Path, out: Path, variant: str, sparse: bool = True) -> Dict[str, Path]:
    """À partir d'une arborescence : boot.img, vbmeta.img, system/vendor en ext4 (mke2fs requis)."""
    from horizonlab.core.tools import run, which

    v = VARIANTS[variant]
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    made: Dict[str, Path] = {}
    ramdisk = gzip.compress(cpio_newc({
        "init": b"#fixture init\n", "first_stage_ramdisk/fstab.hlfixture": b"system /system ext4 ro wait\n",
        "system/etc/ramdisk/build.prop": f"ro.bootimage.build.fingerprint=horizonlab/{v['device']}\n".encode()}))
    kern = fake_kernel(v["kernel"])
    made["boot"] = make_boot_image(out / "boot_a.img", kern, ramdisk, v["boot_header"],
                                   encode_os_version(v["release"], v["patch"]))
    made["vbmeta"] = make_vbmeta(out / "vbmeta_a.img", {"boot": made["boot"].read_bytes()})
    mke2fs = which("mke2fs") or shutil.which("mkfs.ext4")
    if mke2fs:
        for part in ("system", "vendor"):
            raw = out / f"{part}.raw.img"
            r = run([mke2fs, "-q", "-t", "ext4", "-O", "^has_journal", "-I", "256", "-L", part,
                     "-d", str(tree / part), str(raw), "16M"], timeout=120)
            if not r.ok:
                raise RuntimeError(f"mke2fs : {r.stderr}")
            img2simg = shutil.which("img2simg")
            if sparse and img2simg:
                run([img2simg, str(raw), str(out / f"{part}_a.img")], timeout=120)
                raw.unlink()
            else:
                raw.rename(out / f"{part}_a.img")
            made[part] = out / f"{part}_a.img"
    return made


def build_all(dest: Path, images: bool = True) -> Dict[str, Path]:
    dest = Path(dest)
    res = {}
    for var in VARIANTS:
        res[f"tree_{var}"] = build_tree(dest / f"fixture_{var}", var)
        if images:
            try:
                build_images(res[f"tree_{var}"], dest / f"fixture_{var}_images", var)
                res[f"images_{var}"] = dest / f"fixture_{var}_images"
            except RuntimeError:
                pass
    return res
