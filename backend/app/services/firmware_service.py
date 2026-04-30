import asyncio
import hashlib
import os
import re
import shutil
import tarfile
import tempfile
import uuid
import zipfile

import aiofiles
from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.firmware import Firmware


_7Z_MAGIC = b"\x37\x7a\xbc\xaf\x27\x1c"
# 7z's CLI writes password-prompt errors to stderr; match on stable fragments
# rather than the full message (wording varies slightly across p7zip versions).
_7Z_ENCRYPTED_MARKERS = (
    "Cannot open encrypted archive",
    "Wrong password",
    "Can not open encrypted archive",
)


def _sanitize_filename(name: str) -> str:
    """Sanitize a user-supplied filename to prevent path traversal and OS issues.

    Strips directory components, replaces unsafe characters, and limits length.
    """
    # Take only the basename (strip any path components / traversal)
    name = os.path.basename(name)
    # Replace anything that isn't alphanumeric, dot, hyphen, or underscore
    name = re.sub(r"[^\w.\-]", "_", name)
    # Collapse consecutive underscores
    name = re.sub(r"__+", "_", name)
    # Strip leading dots (no hidden files / no "..") and leading underscores
    name = name.lstrip("._")
    # Limit to 200 chars to stay within filesystem limits
    name = name[:200]
    return name or "firmware.bin"


def _zip_is_rootfs(zip_path: str) -> bool:
    """Check if a ZIP archive contains a Linux root filesystem.

    Looks for top-level directory entries matching standard Linux filesystem
    markers (etc/ + bin/ or usr/). Handles both flat rootfs archives and
    archives with a single wrapper directory (e.g. rootfs/etc/, squashfs-root/bin/).
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = {info.filename for info in zf.infolist()}
    except (zipfile.BadZipFile, OSError):
        return False

    # Check for direct top-level rootfs markers
    def _has_markers(prefix: str) -> bool:
        has_etc = any(
            n.startswith(prefix + "etc/") or n == prefix + "etc"
            for n in names
        )
        has_usr_or_bin = any(
            n.startswith(prefix + d) or n == prefix + d.rstrip("/")
            for n in names
            for d in ("usr/", "bin/")
        )
        return has_etc and has_usr_or_bin

    if _has_markers(""):
        return True

    # Check one level deep (e.g. rootfs/etc/, squashfs-root/bin/)
    top_dirs = {n.split("/", 1)[0] for n in names if "/" in n}
    for top in top_dirs:
        if _has_markers(top + "/"):
            return True

    return False


def _extract_firmware_from_zip(zip_path: str, output_dir: str) -> str | None:
    """Extract the main firmware file from a ZIP archive.

    If the ZIP contains a Linux root filesystem (etc/ + bin/ or usr/),
    returns None so the ZIP is passed intact to binwalk, which can extract
    it fully and let the unpack pipeline locate the filesystem root.

    Otherwise picks the largest file in the archive (most likely a firmware
    image wrapped in ZIP). Returns the path to the extracted file, or None
    if the archive is empty.
    """
    if _zip_is_rootfs(zip_path):
        return None

    with zipfile.ZipFile(zip_path, "r") as zf:
        candidates = []
        for info in zf.infolist():
            if info.is_dir():
                continue
            basename = os.path.basename(info.filename)
            # Skip hidden files, macOS resource forks, etc.
            if not basename or basename.startswith(".") or basename.startswith("__"):
                continue
            candidates.append(info)

        if not candidates:
            return None

        best = max(candidates, key=lambda i: i.file_size)
        target_name = _sanitize_filename(os.path.basename(best.filename))
        target_path = os.path.join(output_dir, target_name)

        # Extract in chunks to avoid loading entire file into memory
        with zf.open(best) as src, open(target_path, "wb") as dst:
            while chunk := src.read(8192):
                dst.write(chunk)

        return target_path


def _is_7z_archive(path: str) -> bool:
    """Return True if the file begins with the 7-Zip magic signature.

    Uses magic-bytes detection rather than extension matching because
    vendor OTAs sometimes ship 7z-wrapped firmware with misleading
    extensions (e.g. ``.img``). The 6-byte signature is specific enough
    that false positives are effectively impossible.
    """
    try:
        with open(path, "rb") as f:
            return f.read(len(_7Z_MAGIC)) == _7Z_MAGIC
    except OSError:
        return False


async def _extract_firmware_from_7z(archive_path: str, output_dir: str) -> str | None:
    """Extract the largest file from an unencrypted 7-Zip archive.

    Runs the 7z tool with an empty password so unencrypted archives unwrap
    without ever blocking on a prompt. Extraction goes into a temp
    sub-directory so any path-traversal attempts in the archive are
    contained; only the chosen inner file is moved into output_dir.

    Returns the path to the extracted firmware, or None if the archive
    contained no usable file.

    Raises:
        ValueError: The archive is password-protected. Message starts with
            "Archive is password-protected" so callers can identify it and
            convert to HTTP 400.
        RuntimeError: Extraction failed for another reason (corrupt
            archive, out of disk, etc). Callers may choose to fall back to
            treating the upload as a raw binary.
    """
    extract_dir = tempfile.mkdtemp(prefix="7z_extract_", dir=output_dir)
    try:
        argv = ["7z", "x", f"-o{extract_dir}", "-y", "-p", archive_path]
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        combined = (stdout + stderr).decode("utf-8", errors="replace")

        if proc.returncode != 0:
            if any(marker in combined for marker in _7Z_ENCRYPTED_MARKERS):
                raise ValueError(
                    "Archive is password-protected. Decrypt the archive "
                    "locally and re-upload the inner firmware image."
                )
            raise RuntimeError(
                f"7z extraction failed (exit {proc.returncode}): "
                f"{combined.strip() or 'no output'}"
            )

        largest_path: str | None = None
        largest_size = -1
        for root, _dirs, files in os.walk(extract_dir):
            for name in files:
                if name.startswith(".") or name.startswith("__"):
                    continue
                path = os.path.join(root, name)
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size > largest_size:
                    largest_size = size
                    largest_path = path

        if largest_path is None:
            return None

        target_name = _sanitize_filename(os.path.basename(largest_path))
        target_path = os.path.join(output_dir, target_name)
        # Avoid colliding with the original archive still in output_dir.
        if os.path.exists(target_path):
            base, ext = os.path.splitext(target_name)
            target_path = os.path.join(output_dir, f"{base}_extracted{ext}")
        shutil.move(largest_path, target_path)
        return target_path
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


def _extract_archive(archive_path: str, output_dir: str) -> None:
    """Extract a tar, tar.gz, or zip archive with path traversal prevention."""
    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path) as tf:
            for member in tf.getmembers():
                # Prevent tar slip (path traversal)
                target = os.path.realpath(os.path.join(output_dir, member.name))
                if not target.startswith(os.path.realpath(output_dir) + os.sep) and target != os.path.realpath(output_dir):
                    raise ValueError(f"Path traversal detected in archive: {member.name}")
            tf.extractall(output_dir, filter="data")
    elif zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                target = os.path.realpath(os.path.join(output_dir, info.filename))
                if not target.startswith(os.path.realpath(output_dir) + os.sep) and target != os.path.realpath(output_dir):
                    raise ValueError(f"Path traversal detected in archive: {info.filename}")
            zf.extractall(output_dir)
    else:
        raise ValueError(
            "Unsupported archive format. Please upload a .tar.gz, .tar, or .zip file."
        )


class FirmwareService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.settings = get_settings()

    async def upload(
        self,
        project_id: uuid.UUID,
        file: UploadFile,
        version_label: str | None = None,
    ) -> Firmware:
        # Generate a firmware ID upfront for per-firmware storage directory
        firmware_id = uuid.uuid4()

        # Per-firmware storage: projects/{pid}/firmware/{fid}/
        firmware_dir = os.path.join(
            self.settings.storage_root,
            "projects",
            str(project_id),
            "firmware",
            str(firmware_id),
        )
        os.makedirs(firmware_dir, exist_ok=True)

        # Stream file to disk while computing SHA256
        raw_filename = file.filename or "firmware.bin"
        filename = _sanitize_filename(raw_filename)
        storage_path = os.path.join(firmware_dir, filename)
        sha256_hash = hashlib.sha256()
        file_size = 0

        async with aiofiles.open(storage_path, "wb") as out_file:
            while chunk := await file.read(8192):
                sha256_hash.update(chunk)
                await out_file.write(chunk)
                file_size += len(chunk)

        # If the uploaded file is a ZIP (by extension), extract the firmware from inside it.
        # We check the extension rather than zipfile.is_zipfile() alone because firmware
        # binaries can contain embedded zip data that triggers false positives.
        if raw_filename.lower().endswith(".zip") and zipfile.is_zipfile(storage_path):
            extracted = _extract_firmware_from_zip(storage_path, firmware_dir)
            if extracted:
                os.remove(storage_path)
                storage_path = extracted
                # Recompute hash and size for the actual firmware content
                sha256_hash = hashlib.sha256()
                file_size = 0
                async with aiofiles.open(storage_path, "rb") as f:
                    while chunk := await f.read(8192):
                        sha256_hash.update(chunk)
                        file_size += len(chunk)

        # 7z wrapper — detected by magic bytes because vendor OTAs often ship
        # 7z-wrapped firmware with misleading extensions (e.g. Creality K1 Max
        # ships a 7z OTA as .img). binwalk does not descend into 7z containers,
        # so without this the firmware would appear unrecognizable to the
        # unpack pipeline.
        elif _is_7z_archive(storage_path):
            try:
                extracted = await _extract_firmware_from_7z(storage_path, firmware_dir)
            except RuntimeError:
                # Corrupt or otherwise non-extractable — fall through and let
                # binwalk surface whatever it can. We're no worse off than today.
                extracted = None
            # Note: ValueError (password-protected) intentionally propagates;
            # the router converts it to HTTP 400 so the user gets actionable
            # feedback instead of an unpack failure later.
            if extracted:
                os.remove(storage_path)
                storage_path = extracted
                sha256_hash = hashlib.sha256()
                file_size = 0
                async with aiofiles.open(storage_path, "rb") as f:
                    while chunk := await f.read(8192):
                        sha256_hash.update(chunk)
                        file_size += len(chunk)

        firmware = Firmware(
            id=firmware_id,
            project_id=project_id,
            original_filename=raw_filename,
            sha256=sha256_hash.hexdigest(),
            file_size=file_size,
            storage_path=storage_path,
            version_label=version_label,
        )
        self.db.add(firmware)
        await self.db.flush()
        return firmware

    async def upload_rootfs(
        self,
        firmware: Firmware,
        file: UploadFile,
    ) -> Firmware:
        """Extract a user-supplied rootfs archive into the firmware's extracted dir.

        Accepts .tar.gz, .tar, or .zip archives containing the filesystem root.
        Runs architecture and OS detection on the extracted contents.
        """
        from app.workers.unpack import (
            detect_architecture,
            detect_kernel,
            detect_os_info,
            find_filesystem_root,
        )

        firmware_dir = os.path.dirname(firmware.storage_path)
        extraction_dir = os.path.join(firmware_dir, "extracted")
        os.makedirs(extraction_dir, exist_ok=True)

        # Save archive to a temp file
        raw_filename = file.filename or "rootfs.tar.gz"
        archive_path = os.path.join(firmware_dir, _sanitize_filename(raw_filename))
        async with aiofiles.open(archive_path, "wb") as out:
            while chunk := await file.read(8192):
                await out.write(chunk)

        # Extract the archive
        try:
            _extract_archive(archive_path, extraction_dir)
        finally:
            os.remove(archive_path)

        # Find the filesystem root
        fs_root = find_filesystem_root(extraction_dir)
        if not fs_root:
            raise ValueError(
                "Could not locate a filesystem root in the archive. "
                "Ensure it contains a Linux root filesystem with at least two "
                "of: bin/, sbin/, etc/, usr/, lib/, var/, init/, ko/."
            )

        firmware.extracted_path = fs_root
        arch, endian = detect_architecture(fs_root)
        firmware.architecture = arch
        firmware.endianness = endian
        firmware.os_info = detect_os_info(fs_root)
        firmware.kernel_path = detect_kernel(extraction_dir, fs_root)
        firmware.unpack_log = "Filesystem provided via manual rootfs upload."

        await self.db.flush()
        return firmware

    async def get_by_project(self, project_id: uuid.UUID) -> Firmware | None:
        """Get the first firmware for a project (backward compat)."""
        result = await self.db.execute(
            select(Firmware)
            .where(Firmware.project_id == project_id)
            .order_by(Firmware.created_at)
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, firmware_id: uuid.UUID) -> Firmware | None:
        """Get a specific firmware by its ID."""
        result = await self.db.execute(
            select(Firmware).where(Firmware.id == firmware_id)
        )
        return result.scalar_one_or_none()

    async def list_by_project(self, project_id: uuid.UUID) -> list[Firmware]:
        """List all firmware for a project, ordered by creation time."""
        result = await self.db.execute(
            select(Firmware)
            .where(Firmware.project_id == project_id)
            .order_by(Firmware.created_at)
        )
        return list(result.scalars().all())

    async def delete(self, firmware: Firmware) -> None:
        """Delete a firmware record and its files on disk."""
        # Remove files from disk
        if firmware.storage_path:
            # The firmware directory is the parent of the storage_path
            firmware_dir = os.path.dirname(firmware.storage_path)
            if os.path.isdir(firmware_dir):
                shutil.rmtree(firmware_dir, ignore_errors=True)
        elif firmware.extracted_path:
            # Fallback: remove extracted path's parent
            parent = os.path.dirname(firmware.extracted_path)
            if os.path.isdir(parent):
                shutil.rmtree(parent, ignore_errors=True)

        await self.db.delete(firmware)
        await self.db.flush()
