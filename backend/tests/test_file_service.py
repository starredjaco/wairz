"""Unit tests for FileService — multi-namespace path canonicalization.

Regression tests for Bug 2: search_files used to return paths with ``..`` segments
when walking from ``/`` with ``extraction_dir`` set, because the prefix was
computed once for the whole walk against ``extracted_root`` while the walk
actually crossed siblings of ``extracted_root``.
"""
from __future__ import annotations

import os
from pathlib import Path

from app.services.file_service import FileService


def _make_dirs(base: Path, layout: dict) -> None:
    for name, contents in layout.items():
        path = base / name
        if isinstance(contents, dict):
            path.mkdir(parents=True, exist_ok=True)
            _make_dirs(path, contents)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"" if contents is None else contents)


class TestToVirtualPath:
    def test_legacy_mode_no_extraction_dir(self, tmp_path: Path):
        # Without extraction_dir, virtual paths are just rooted at extracted_root.
        _make_dirs(tmp_path, {"rootfs": {"bin": {"foo": None}}})
        svc = FileService(str(tmp_path / "rootfs"))
        assert svc.to_virtual_path(str(tmp_path / "rootfs" / "bin" / "foo")) == "/bin/foo"
        assert svc.to_virtual_path(str(tmp_path / "rootfs")) == "/"
        # Outside the sandbox returns None.
        assert svc.to_virtual_path("/etc/passwd") is None

    def test_virtual_mode_rootfs_paths(self, tmp_path: Path):
        _make_dirs(tmp_path, {
            "outer": {
                "squashfs-root": {"bin": {"foo": None}},
                "sibling.bin": b"\x00" * 200,
            },
        })
        svc = FileService(
            str(tmp_path / "outer" / "squashfs-root"),
            extraction_dir=str(tmp_path / "outer"),
        )
        assert svc.to_virtual_path(
            str(tmp_path / "outer" / "squashfs-root" / "bin" / "foo")
        ) == "/rootfs/bin/foo"
        assert svc.to_virtual_path(
            str(tmp_path / "outer" / "squashfs-root")
        ) == "/rootfs"

    def test_virtual_mode_extraction_dir_siblings(self, tmp_path: Path):
        # Files at extraction_dir level (siblings of the rootfs) get plain
        # /<basename> paths — never /rootfs/../<basename>.
        _make_dirs(tmp_path, {
            "outer": {
                "squashfs-root": {"bin": {}},
                "kernel.bin": b"\x00",
                "blob.dat": b"\x01",
            },
        })
        svc = FileService(
            str(tmp_path / "outer" / "squashfs-root"),
            extraction_dir=str(tmp_path / "outer"),
        )
        assert svc.to_virtual_path(str(tmp_path / "outer" / "kernel.bin")) == "/kernel.bin"
        assert svc.to_virtual_path(str(tmp_path / "outer" / "blob.dat")) == "/blob.dat"

    def test_virtual_mode_partition_namespace(self, tmp_path: Path):
        # An extra *-root directory gets its own virtual namespace.
        _make_dirs(tmp_path, {
            "outer": {
                "squashfs-root": {"bin": {}},
                "jffs2-root": {"data": {"x": None}},
            },
        })
        svc = FileService(
            str(tmp_path / "outer" / "squashfs-root"),
            extraction_dir=str(tmp_path / "outer"),
        )
        assert svc.to_virtual_path(
            str(tmp_path / "outer" / "jffs2-root" / "data" / "x")
        ) == "/jffs2-root/data/x"

    def test_outside_sandbox_returns_none(self, tmp_path: Path):
        _make_dirs(tmp_path, {"outer": {"squashfs-root": {"bin": {}}}})
        svc = FileService(
            str(tmp_path / "outer" / "squashfs-root"),
            extraction_dir=str(tmp_path / "outer"),
        )
        assert svc.to_virtual_path("/etc/passwd") is None
        assert svc.to_virtual_path(str(tmp_path / "totally_elsewhere")) is None


class TestSearchFilesNoDotDot:
    def test_search_root_does_not_emit_dotdot(self, tmp_path: Path):
        # Regression: pre-fix, search_files("/", "*") produced paths like
        # /rootfs/../../<file> for files at extraction_dir level. After fix,
        # those should appear as /<file>.
        _make_dirs(tmp_path, {
            "outer": {
                "squashfs-root": {
                    "bin": {"busybox": None, "ls": None},
                    "etc": {"passwd": None},
                },
                "ppstool": b"\x7fELF" + b"\x00" * 100,
                "cacert.pem": b"-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----",
            },
        })

        svc = FileService(
            str(tmp_path / "outer" / "squashfs-root"),
            extraction_dir=str(tmp_path / "outer"),
        )
        matches, _ = svc.search_files("*", "/")

        # No path may contain `..`
        for m in matches:
            assert ".." not in m, f"search_files emitted dotdot path: {m}"

        # Specific expectations: rootfs files prefixed, sibling files at top.
        assert "/ppstool" in matches
        assert "/cacert.pem" in matches
        assert "/rootfs/bin/busybox" in matches
        assert "/rootfs/etc/passwd" in matches

    def test_search_results_are_dereferenceable(self, tmp_path: Path):
        # Every path returned by search_files should be acceptable to file_info
        # (which routes through _resolve and validate_path).
        _make_dirs(tmp_path, {
            "outer": {
                "squashfs-root": {"bin": {"foo": b"hello"}},
                "kernel": b"\x00" * 200,
            },
        })
        svc = FileService(
            str(tmp_path / "outer" / "squashfs-root"),
            extraction_dir=str(tmp_path / "outer"),
        )
        matches, _ = svc.search_files("*", "/")
        for m in matches:
            # _resolve raises PathTraversalError on bad paths; we just want it
            # to succeed and resolve to a real file or directory we found.
            real = svc._resolve(m)
            assert os.path.exists(real), f"resolved {m} → {real} which doesn't exist"

    def test_search_inside_rootfs_unchanged(self, tmp_path: Path):
        # When walking inside /rootfs/, the existing prefix logic worked — make
        # sure the new code preserves that.
        _make_dirs(tmp_path, {
            "outer": {
                "squashfs-root": {
                    "bin": {"busybox": None, "ls": None},
                    "etc": {"passwd": None},
                },
            },
        })
        svc = FileService(
            str(tmp_path / "outer" / "squashfs-root"),
            extraction_dir=str(tmp_path / "outer"),
        )
        matches, _ = svc.search_files("*", "/rootfs/bin")
        assert "/rootfs/bin/busybox" in matches
        assert "/rootfs/bin/ls" in matches
