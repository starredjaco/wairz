import asyncio
import glob
import os
from dataclasses import dataclass, field

from elftools.elf.elffile import ELFFile


@dataclass
class UnpackResult:
    extracted_path: str | None = None
    extraction_dir: str | None = None
    architecture: str | None = None
    endianness: str | None = None
    os_info: str | None = None
    kernel_path: str | None = None
    firmware_kind: str = "unknown"
    rtos_flavor: str | None = None
    unpack_log: str = ""
    success: bool = False
    error: str | None = None


# Map ELF machine types to friendly names
_ELF_ARCH_MAP = {
    "EM_MIPS": "mips",
    "EM_ARM": "arm",
    "EM_AARCH64": "aarch64",
    "EM_386": "x86",
    "EM_X86_64": "x86_64",
    "EM_PPC": "ppc",
    "EM_PPC64": "ppc64",
    "EM_SH": "sh",
    "EM_SPARC": "sparc",
}


async def run_binwalk_extraction(firmware_path: str, output_dir: str, timeout: int = 1800) -> str:
    """Run binwalk with matryoshka recursion to extract firmware contents.

    -M enables matryoshka mode so binwalk re-scans its own outputs; -d 5 caps
    recursion depth to keep wall-clock bounded. The post-binwalk dispatcher
    in ``fs_extractors.py`` picks up any filesystems binwalk's signature
    scanner missed (e.g. vendor-modified SquashFS).
    """
    proc = await asyncio.create_subprocess_exec(
        "binwalk", "-Me", "-d", "5", "-C", output_dir, firmware_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"binwalk extraction timed out after {timeout}s")

    return stdout.decode(errors="replace").replace("\x00", "")


# Standard Linux/embedded filesystem layout names. We require >= _MIN_MARKERS
# of these to consider a directory a plausible rootfs. Note this includes some
# vendor-specific names (init, ko) seen in real embedded images that don't ship
# /etc — e.g. Wyze cameras put config in /init/.
_FS_MARKER_NAMES = frozenset({
    "bin", "sbin", "etc", "etc_ro", "usr", "lib", "lib64",
    "var", "tmp", "dev", "proc", "sys", "root", "home",
    "init", "ko", "mnt", "opt", "boot", "run",
})

_MIN_MARKERS = 2


def _count_fs_markers(path: str) -> int:
    """Count standard Linux/embedded filesystem layout names at *path*."""
    try:
        entries = set(os.listdir(path))
    except OSError:
        return 0
    return len(entries & _FS_MARKER_NAMES)


def _has_linux_markers(path: str) -> bool:
    """Whether *path* looks like a Linux/embedded filesystem root.

    Requires at least ``_MIN_MARKERS`` of the standard layout names. We don't
    hard-require ``/etc`` because real embedded firmware (Wyze, some Ingenic
    SoCs) ships config in vendor dirs like ``/init/`` instead.
    """
    return _count_fs_markers(path) >= _MIN_MARKERS


def find_filesystem_root(extraction_dir: str) -> str | None:
    """Find the extracted filesystem root.

    Strategy (preferring shallow, known-named roots over deep heuristic matches):

    1. If a directory whose name matches a known binwalk root pattern
       (``squashfs-root``, ``jffs2-root``, ``squashfs-root-0`` etc.) exists,
       prefer the SHALLOWEST one. Tie-break on marker count, then path.
       Stop descending into named roots — anything inside one is *part of*
       that rootfs, not a separate candidate.

    2. Otherwise, fall back to any directory with >= ``_MIN_MARKERS`` standard
       layout names. Again prefer shallowest. Prune the walk on a hit so we
       don't pick e.g. ``bin/busybox/bin/`` over the actual rootfs.

    3. Otherwise return ``None``. We deliberately do NOT fall back to "largest
       directory by entry count" — that bug picked busybox-installed bin/
       trees as the mount root for any firmware lacking /etc.
    """
    extraction_real = os.path.realpath(extraction_dir)
    base_depth = extraction_real.count(os.sep)

    # (depth, -marker_count, path) — sorted ascending picks shallowest, then
    # most markers, then lexical path order for stable results.
    named_candidates: list[tuple[int, int, str]] = []
    marker_candidates: list[tuple[int, int, str]] = []

    for root, dirs, _files in os.walk(extraction_dir):
        # Skip the extraction_dir itself — it'll never be a rootfs.
        if os.path.realpath(root) == extraction_real:
            continue

        depth = os.path.realpath(root).count(os.sep) - base_depth
        dirname = os.path.basename(root)
        marker_count = _count_fs_markers(root)

        if _ROOT_DIR_RE.match(dirname):
            named_candidates.append((depth, -marker_count, root))
            # Don't descend into a named root — its children are not separate
            # rootfs candidates.
            dirs.clear()
            continue

        if marker_count >= _MIN_MARKERS:
            marker_candidates.append((depth, -marker_count, root))
            # Prune to avoid picking nested busybox/bin-style sub-roots.
            dirs.clear()

    if named_candidates:
        named_candidates.sort()
        return named_candidates[0][2]

    if marker_candidates:
        marker_candidates.sort()
        return marker_candidates[0][2]

    return None


def detect_architecture(fs_root: str) -> tuple[str | None, str | None]:
    """Detect architecture and endianness by examining ELF binaries.

    Uses majority voting across all ELF binaries found in common directories
    to handle mixed-architecture filesystems (e.g., ARM firmware with x86-64
    systemd from a host layer).
    """
    from collections import Counter

    # Look for ELF binaries in common dirs
    search_dirs = ["bin", "usr/bin", "sbin", "usr/sbin", "lib"]
    votes: Counter[tuple[str, str]] = Counter()
    max_scan = 50  # Cap scanning to avoid slowness on huge filesystems

    for search_dir in search_dirs:
        search_path = os.path.join(fs_root, search_dir)
        if not os.path.isdir(search_path):
            continue

        try:
            entries = os.listdir(search_path)
        except OSError:
            continue

        for entry in entries:
            if sum(votes.values()) >= max_scan:
                break

            full_path = os.path.join(search_path, entry)
            if not os.path.isfile(full_path):
                continue
            try:
                with open(full_path, "rb") as f:
                    magic = f.read(4)
                    if magic != b"\x7fELF":
                        continue
                    f.seek(0)
                    elf = ELFFile(f)
                    arch = _ELF_ARCH_MAP.get(elf.header.e_machine, elf.header.e_machine)
                    endianness = "little" if elf.little_endian else "big"

                    # For MIPS, distinguish mips vs mipsel
                    if arch == "mips" and endianness == "little":
                        arch = "mipsel"

                    votes[(arch, endianness)] += 1
            except Exception:
                continue

    if not votes:
        return None, None

    # Return the most common architecture
    (arch, endianness), _count = votes.most_common(1)[0]
    return arch, endianness


def detect_os_info(fs_root: str) -> str | None:
    """Read OS info from standard release files."""
    release_files = [
        "etc/os-release",
        "etc/openwrt_release",
        "etc/lsb-release",
        "etc/version",
        "etc/issue",
    ]
    for rel_file in release_files:
        full_path = os.path.join(fs_root, rel_file)
        if os.path.isfile(full_path):
            try:
                with open(full_path) as f:
                    content = f.read(1024)
                # Strip null bytes — firmware may have zeroed-out placeholder files
                content = content.replace("\x00", "").strip()
                if content:
                    return content
            except Exception:
                continue
    return None


def _read_magic(path: str, num_bytes: int = 4) -> bytes:
    """Read the first N bytes of a file for magic number detection."""
    try:
        with open(path, "rb") as f:
            return f.read(num_bytes)
    except OSError:
        return b""


# Known filesystem root directory names produced by binwalk extraction
_FS_ROOT_NAMES = frozenset({
    "ext-root", "squash-root", "squashfs-root", "ubifs-root",
    "cpio-root", "jffs2-root", "cramfs-root", "romfs-root",
})

# Filename patterns that strongly indicate a kernel image
_KERNEL_NAME_PATTERNS = ("vmlinux", "zimage", "uimage", "bzimage")

# File extensions for filesystem images — NOT kernels
_FS_IMAGE_EXTENSIONS = frozenset({
    ".ext", ".ext2", ".ext3", ".ext4",
    ".yaffs", ".yaffs2",
    ".jffs2",
    ".squashfs", ".sqfs",
    ".cramfs",
    ".ubifs", ".ubi",
    ".romfs",
    ".cpio",
})


import re as _re

_ROOT_DIR_RE = _re.compile(r"^[a-z0-9]+-root(-\d+)?$")


def _find_binwalk_output_dir(
    fs_root_real: str, extraction_dir_real: str
) -> str | None:
    """Walk up from the rootfs to find the binwalk output directory.

    The binwalk output dir is the directory that contains the rootfs
    *and* possibly other extracted partitions (jffs2-root, ext-root, etc.).
    We walk up from the rootfs toward extraction_dir, and pick the deepest
    ancestor that contains at least one sibling ``*-root`` directory or
    other content worth showing at the virtual top level.

    For nested -Me extractions the rootfs can be several levels deep:
        extracted/_fw.bin.extracted/_100.squashfs.extracted/squashfs-root/
    In that case we want the ``_100.squashfs.extracted/`` directory so its
    sibling ``ext-root/`` etc. are visible.

    Returns the binwalk output dir path, or None if the virtual top-level
    would add no value (e.g. single rootfs with no siblings).
    """
    # Walk up from rootfs parent toward (and including) extraction_dir
    current = os.path.dirname(fs_root_real)
    rootfs_basename = os.path.basename(fs_root_real)
    best = None

    while current.startswith(extraction_dir_real):
        # Check if this directory has interesting siblings / children
        try:
            entries = os.listdir(current)
        except OSError:
            if current == extraction_dir_real:
                break
            current = os.path.dirname(current)
            continue

        has_other_root = False
        has_large_file = False
        for name in entries:
            if name == rootfs_basename:
                continue
            full = os.path.join(current, name)
            if os.path.isdir(full):
                if _ROOT_DIR_RE.match(name):
                    has_other_root = True
                    break
                # Also look one level inside subdirectories (for nested
                # _*.extracted/ dirs that contain *-root directories)
                try:
                    for child in os.listdir(full):
                        child_full = os.path.join(full, child)
                        if os.path.isdir(child_full) and _ROOT_DIR_RE.match(child):
                            # Make sure it's not the rootfs itself
                            if os.path.realpath(child_full) != fs_root_real:
                                has_other_root = True
                                break
                except OSError:
                    pass
                if has_other_root:
                    break
            elif os.path.isfile(full):
                try:
                    if os.path.getsize(full) >= 100_000:
                        has_large_file = True
                except OSError:
                    pass

        if has_other_root or has_large_file:
            best = current
            break  # Use the deepest dir with siblings

        if current == extraction_dir_real:
            break
        current = os.path.dirname(current)

    return best


def detect_kernel(extraction_dir: str, fs_root: str | None) -> str | None:
    """Scan the extraction directory for a kernel image.

    Kernels extracted by binwalk appear as siblings to the filesystem root
    in the .extracted/ directory — they are NOT inside the filesystem.

    Returns the absolute path to the best kernel candidate, or None.
    """
    # The parent of the filesystem root is the binwalk extraction output dir
    # (e.g., /data/.../extracted/_firmware.img.extracted/)
    if fs_root:
        scan_dir = os.path.dirname(fs_root)
    else:
        # No filesystem root found — scan all .extracted/ subdirectories
        scan_dir = extraction_dir

    if not os.path.isdir(scan_dir):
        return None

    candidates: list[tuple[str, int]] = []  # (path, priority)

    for entry in os.scandir(scan_dir):
        if not entry.is_file(follow_symlinks=False):
            continue

        name_lower = entry.name.lower()

        # Skip filesystem images and known roots
        if name_lower in _FS_ROOT_NAMES:
            continue
        # Skip JSON sidecar files and very small files
        if name_lower.endswith(".json") or name_lower.endswith(".txt"):
            continue
        # Skip filesystem image files (ext2, yaffs, jffs2, etc.)
        _, ext = os.path.splitext(name_lower)
        if ext in _FS_IMAGE_EXTENSIONS:
            continue

        try:
            file_size = entry.stat().st_size
        except OSError:
            continue

        # Kernels are typically > 500 KB
        if file_size < 500_000:
            continue

        # 1) Check filename patterns (highest priority)
        if any(p in name_lower for p in _KERNEL_NAME_PATTERNS):
            candidates.append((entry.path, 100))
            continue

        # 2) Check magic bytes
        magic = _read_magic(entry.path, 4)

        # ELF binary — could be an uncompressed vmlinux
        if magic == b"\x7fELF":
            # Verify it's an executable (not a shared library from extraction)
            try:
                with open(entry.path, "rb") as f:
                    elf = ELFFile(f)
                    # Kernel ELFs are ET_EXEC (type 2) and very large
                    if elf.header.e_type == "ET_EXEC" and file_size > 1_000_000:
                        candidates.append((entry.path, 95))
                        continue
            except Exception:
                pass

        # U-Boot uImage header
        if magic == b"\x27\x05\x19\x56":
            candidates.append((entry.path, 90))
            continue

        # ARM Linux zImage magic at offset 0x24: 0x016f2818
        if file_size > 1_000_000:
            try:
                with open(entry.path, "rb") as f:
                    f.seek(0x24)
                    arm_magic = f.read(4)
                    if arm_magic == b"\x18\x28\x6f\x01":
                        candidates.append((entry.path, 92))
                        continue
            except OSError:
                pass

        # gzip-compressed (possibly compressed kernel)
        if magic[:2] == b"\x1f\x8b" and file_size > 1_000_000:
            candidates.append((entry.path, 70))
            continue

        # LZMA-compressed
        if magic[:3] == b"\x5d\x00\x00" and file_size > 1_000_000:
            candidates.append((entry.path, 70))
            continue

    if not candidates:
        return None

    # Return highest-priority candidate
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]


async def unpack_firmware(firmware_path: str, output_base_dir: str) -> UnpackResult:
    """Orchestrate the full unpacking pipeline."""
    from .fs_extractors import recursive_extract

    result = UnpackResult()

    # Step 1: Run binwalk extraction
    try:
        extraction_dir = os.path.join(output_base_dir, "extracted")
        os.makedirs(extraction_dir, exist_ok=True)
        result.unpack_log = await run_binwalk_extraction(firmware_path, extraction_dir)
    except TimeoutError as e:
        result.error = str(e)
        result.unpack_log = str(e)
        return result
    except Exception as e:
        result.error = f"Extraction failed: {e}"
        result.unpack_log = str(e)
        return result

    # Step 1b: Custom recursive pass for filesystem images binwalk missed
    # (e.g. vendor-modified SquashFS that needs sasquatch, or UBI/JFFS2
    # blobs binwalk extracted but didn't further unpack). Log-and-continue
    # on failures; never fails the overall unpack.
    try:
        original_size = os.path.getsize(firmware_path)
    except OSError:
        original_size = None
    dispatcher_log = await recursive_extract(
        extraction_dir, original_size=original_size
    )
    result.unpack_log = (result.unpack_log or "") + "\n" + dispatcher_log

    # Step 2: Find the filesystem root (Linux signal)
    fs_root = find_filesystem_root(extraction_dir)

    # Step 2a: Classify the firmware kind. If we found a rootfs, the
    # detector trusts that; otherwise it scans the raw image and any
    # extracted blobs for RTOS signatures.
    from app.services.rtos_detection_service import detect_firmware_kind

    detection = detect_firmware_kind(firmware_path, extraction_dir, fs_root)
    result.firmware_kind = detection.kind
    result.rtos_flavor = detection.flavor
    result.unpack_log = (result.unpack_log or "") + f"\nkind detection: {detection.notes}"

    if not fs_root:
        # Non-Linux path: only succeed if we positively recognised an
        # RTOS. An unknown image has no rootfs to mount and no RTOS
        # workflow to run, so keep the error behaviour the frontend
        # already handles (offer to upload-rootfs).
        if detection.kind == "rtos":
            result.success = True
        else:
            result.error = "Could not locate filesystem root in extracted contents"
        return result

    result.extracted_path = fs_root

    # Step 2b: Determine the binwalk output directory (parent of rootfs).
    # Walk up from the rootfs to find the directory that contains it and
    # possibly other extracted partitions (jffs2-root, ext-root, etc.).
    # This handles both simple layouts (rootfs one level deep) and nested
    # binwalk -Me extractions (rootfs several levels deep).
    fs_root_real = os.path.realpath(fs_root)
    extraction_dir_real = os.path.realpath(extraction_dir)
    if fs_root_real != extraction_dir_real:
        result.extraction_dir = _find_binwalk_output_dir(
            fs_root_real, extraction_dir_real
        )

    # Step 3: Detect architecture
    arch, endian = detect_architecture(fs_root)
    result.architecture = arch
    result.endianness = endian

    # Step 4: Detect OS info
    result.os_info = detect_os_info(fs_root)

    # Step 5: Detect kernel image
    result.kernel_path = detect_kernel(extraction_dir, fs_root)

    result.success = True
    return result
