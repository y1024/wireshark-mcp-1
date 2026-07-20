"""Path traversal / filter injection hardening tests."""

from __future__ import annotations

from unittest.mock import patch

from wireshark_mcp.security import (
    validate_bpf_filter,
    validate_display_filter,
    validate_pcap_read_path,
    validate_pcap_write_path,
    validate_target_host,
)


def test_bpf_rejects_shell_metacharacters() -> None:
    ok, err = validate_bpf_filter("port 80; id")
    assert ok is None and err
    ok, err = validate_bpf_filter("host 1.2.3.4")
    assert ok == "host 1.2.3.4" and err is None


def test_display_filter_allows_quotes_rejects_control() -> None:
    ok, err = validate_display_filter('http.host == "example.com"')
    assert ok is not None and err is None
    ok, err = validate_display_filter("tcp\nid")
    assert ok is None and err


def test_target_host_rejects_injection() -> None:
    host, err = validate_target_host('1.2.3.4; id')
    assert host is None and err
    host, err = validate_target_host("example.com")
    assert host == "example.com"


def test_pcap_write_blocks_traversal(tmp_path) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    path, err = validate_pcap_write_path(
        "../evil.pcap", captures_dir=str(captures)
    )
    assert path is None and err
    path, err = validate_pcap_write_path(
        "ok.pcap", captures_dir=str(captures)
    )
    assert path is not None and path.endswith("ok.pcap")


def test_pcap_read_requires_existing_suffix(tmp_path) -> None:
    bad = tmp_path / "note.txt"
    bad.write_text("x", encoding="utf-8")
    path, err = validate_pcap_read_path(str(bad))
    assert path is None and err

    good = tmp_path / "sample.pcap"
    good.write_bytes(b"\x00" * 24)
    path, err = validate_pcap_read_path(str(good))
    assert path == str(good.resolve())
