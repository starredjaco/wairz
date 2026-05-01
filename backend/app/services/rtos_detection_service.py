"""RTOS firmware-kind detection.

Single-pass classifier invoked at the tail of the unpack pipeline. The
strongest signal is the existence of a Linux filesystem root — if
``find_filesystem_root`` succeeded, we are looking at Linux. Otherwise we
scan the raw firmware image and any extracted ELF/blob siblings for
known RTOS signatures and return ``(kind, flavor)``.

We are deliberately conservative: only the v1-supported flavors
(``freertos``, ``zephyr``, ``baremetal-cortexm``) ever get reported. An
ambiguous or unrecognised image returns ``("unknown", None)`` so the user
can override via the kind dropdown.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile


# String markers — byte literals so we can scan raw binaries without
# decoding. Each tuple is (marker, weight). We require either one
# weight>=2 hit or two weight==1 hits to call a flavor.
_FREERTOS_MARKERS: tuple[tuple[bytes, int], ...] = (
    (b"xTaskCreate", 2),
    (b"pxCurrentTCB", 2),
    (b"vTaskStartScheduler", 2),
    (b"FreeRTOS", 1),
    (b"vTaskDelay", 1),
    (b"prvIdleTask", 1),
    (b"xQueueGenericSend", 1),
)

_ZEPHYR_MARKERS: tuple[tuple[bytes, int], ...] = (
    (b"Booting Zephyr OS", 3),
    (b"ZEPHYR_BASE", 2),
    (b"z_thread_", 1),
    (b"k_thread_create", 1),
    (b"_ZEPHYR_", 1),
    (b"sys_clock_announce", 1),
)

# Heuristics for baremetal Cortex-M: we look for ARM ELFs *without* any
# of the above RTOS markers and with a vector-table-like layout.
_FLAVOR_THRESHOLD = 2  # cumulative weight needed to call a match

# How much of each candidate file to scan. Most RTOS images are small
# (< 4 MB); cap at 16 MB so a misclassified Linux blob doesn't blow
# memory if it gets here.
_SCAN_BUDGET_BYTES = 16 * 1024 * 1024


@dataclass
class KindDetection:
    kind: str  # "linux" | "rtos" | "unknown"
    flavor: str | None
    notes: str


def _score_markers(
    blob: bytes, markers: tuple[tuple[bytes, int], ...]
) -> int:
    """Sum weights of every marker present in *blob*."""
    return sum(weight for marker, weight in markers if marker in blob)


def _read_capped(path: str, cap: int = _SCAN_BUDGET_BYTES) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(cap)
    except OSError:
        return b""


def _candidate_files(
    firmware_path: str, extraction_dir: str | None
) -> list[str]:
    """Files worth scanning for RTOS signatures.

    Always include the original firmware image. If we have an extraction
    directory, also include any ELFs and any large flat binaries siblings
    found in it (those are usually the kernel/firmware blob binwalk
    surfaced from a wrapping container format).
    """
    seen: set[str] = set()
    out: list[str] = []

    def _add(p: str) -> None:
        rp = os.path.realpath(p)
        if rp in seen:
            return
        seen.add(rp)
        out.append(p)

    if os.path.isfile(firmware_path):
        _add(firmware_path)

    if not extraction_dir or not os.path.isdir(extraction_dir):
        return out

    # Walk the extraction tree, collecting ELFs and big flat blobs. Cap
    # at ~30 candidates so degenerate trees don't make us scan forever.
    max_candidates = 30
    for root, _dirs, files in os.walk(extraction_dir):
        for name in files:
            if len(out) >= max_candidates:
                return out
            full = os.path.join(root, name)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            # Skip tiny files; signatures don't fit
            if size < 1024:
                continue
            ext = os.path.splitext(name)[1].lower()
            # Skip JSON/log sidecars binwalk leaves around
            if ext in {".json", ".txt", ".log"}:
                continue
            _add(full)

    return out


def _detect_freertos_or_zephyr(
    candidates: list[str],
) -> tuple[str | None, str]:
    """Return ``(flavor, notes)`` if any candidate matches FreeRTOS/Zephyr."""
    best: tuple[int, str | None, str] = (0, None, "")  # (score, flavor, source path)

    for path in candidates:
        blob = _read_capped(path)
        if not blob:
            continue
        for flavor, markers in (
            ("freertos", _FREERTOS_MARKERS),
            ("zephyr", _ZEPHYR_MARKERS),
        ):
            score = _score_markers(blob, markers)
            if score >= _FLAVOR_THRESHOLD and score > best[0]:
                best = (score, flavor, path)

    if best[1] is None:
        return None, ""
    return best[1], f"matched {best[1]} markers (score={best[0]}) in {os.path.basename(best[2])}"


def _looks_like_cortex_m_elf(path: str) -> bool:
    """Whether *path* is an ARM ELF that walks like baremetal Cortex-M.

    Heuristic: ARM ELF (e_machine == EM_ARM) with ARM v6-M / v7-M / v8-M
    architecture tag, OR a section called ``.isr_vector`` / a symbol
    ``Reset_Handler``. We can't reliably read attributes from every
    toolchain output so we look at multiple weak signals.
    """
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return False
            f.seek(0)
            elf = ELFFile(f)
            if elf.header.e_machine != "EM_ARM":
                return False

            # .isr_vector is the canonical Cortex-M vector-table section
            # name across CMSIS and Zephyr/STM32/NXP startup files.
            for section in elf.iter_sections():
                name = section.name or ""
                if name in (".isr_vector", ".vectors", ".vector_table"):
                    return True

            # Symbol fallback — Reset_Handler is the ARM-Cortex-M ABI
            # convention; ARM A-profile uses _start instead.
            symtab = elf.get_section_by_name(".symtab")
            if symtab is not None:
                for sym in symtab.iter_symbols():
                    if sym.name in ("Reset_Handler", "g_pfnVectors"):
                        return True
    except Exception:
        return False
    return False


def _looks_like_cortex_m_raw(path: str) -> bool:
    """Heuristic vector-table check on a raw (non-ELF) firmware blob.

    Cortex-M reset state: word 0 = initial SP (must point into RAM),
    word 1 = Reset_Handler address (must be in flash with the Thumb bit
    set, i.e. odd). We sample a handful of vendor RAM/flash splits — the
    common ones, not exhaustively.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(8)
            if len(head) < 8:
                return False
    except OSError:
        return False

    initial_sp, reset_handler = struct.unpack("<II", head)

    # Reset handler must have the Thumb bit set on Cortex-M
    if reset_handler & 1 == 0:
        return False

    # Initial SP commonly lives in 0x20000000 (SRAM) or 0x10000000.
    # Reset handler commonly lives in 0x00000000 (alias), 0x08000000
    # (STM32 flash), 0x00100000 (NXP), 0x00010000 (TI). We accept these
    # ranges as evidence; one false positive is cheaper than a miss
    # because the user can override.
    sp_ok = (
        0x20000000 <= initial_sp <= 0x2FFFFFFF
        or 0x10000000 <= initial_sp <= 0x1FFFFFFF
    )
    reset_target = reset_handler & ~1
    rh_ok = (
        reset_target < 0x00200000  # generic flash low region
        or 0x08000000 <= reset_target <= 0x08FFFFFF  # STM32
        or 0x10000000 <= reset_target <= 0x1FFFFFFF  # NXP / Nordic
    )
    return sp_ok and rh_ok


def _detect_baremetal_cortex_m(candidates: list[str]) -> tuple[bool, str]:
    """Check whether any candidate looks like baremetal Cortex-M."""
    for path in candidates:
        if _looks_like_cortex_m_elf(path):
            return True, f"Cortex-M ELF layout in {os.path.basename(path)}"
        if _looks_like_cortex_m_raw(path):
            return True, f"Cortex-M reset vector in {os.path.basename(path)}"
    return False, ""


def detect_firmware_kind(
    firmware_path: str,
    extraction_dir: str | None,
    fs_root: str | None,
) -> KindDetection:
    """Classify a firmware image as Linux, RTOS, or unknown.

    *fs_root* should be the result of ``find_filesystem_root``. When it
    is non-None we trust it and short-circuit to ``linux``.
    """
    if fs_root is not None:
        return KindDetection(kind="linux", flavor=None, notes="filesystem root located")

    candidates = _candidate_files(firmware_path, extraction_dir)
    if not candidates:
        return KindDetection(kind="unknown", flavor=None, notes="no candidate files to scan")

    flavor, notes = _detect_freertos_or_zephyr(candidates)
    if flavor is not None:
        return KindDetection(kind="rtos", flavor=flavor, notes=notes)

    is_cm, cm_notes = _detect_baremetal_cortex_m(candidates)
    if is_cm:
        return KindDetection(kind="rtos", flavor="baremetal-cortexm", notes=cm_notes)

    return KindDetection(
        kind="unknown",
        flavor=None,
        notes="no Linux rootfs and no recognised RTOS signatures",
    )
