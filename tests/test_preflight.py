"""Preflight / dependency gating tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wireshark_mcp.preflight import (
    resolve_tshark,
    run_preflight,
    write_mcp_json,
)


def test_run_preflight_returns_report():
    report = run_preflight()
    assert isinstance(report.ok, bool)
    assert isinstance(report.messages, list)
    assert report.python_ok is True


def test_resolve_tshark_honors_env(monkeypatch, tmp_path):
    fake = tmp_path / ("tshark.exe" if __import__("os").name == "nt" else "tshark")
    fake.write_text("", encoding="utf-8")
    monkeypatch.setenv("TSHARK_PATH", str(fake))
    assert resolve_tshark() == fake


def test_resolve_tshark_missing(monkeypatch):
    monkeypatch.delenv("TSHARK_PATH", raising=False)
    monkeypatch.delenv("WIRESHARK_BIN", raising=False)
    monkeypatch.delenv("WIRESHARK_PATH", raising=False)
    monkeypatch.setattr("wireshark_mcp.preflight.shutil.which", lambda _: None)
    monkeypatch.setattr(
        "wireshark_mcp.preflight.DEFAULT_WINDOWS_TSHARK",
        Path("/nonexistent/tshark.exe"),
    )
    monkeypatch.setattr(
        "wireshark_mcp.preflight.DEFAULT_UNIX_CANDIDATES",
        (Path("/nonexistent/tshark"),),
    )
    assert resolve_tshark() is None


def test_write_mcp_json_sets_tshark_path(tmp_path):
    mcp_json = tmp_path / ".cursor" / "mcp.json"
    python = Path("/usr/bin/python")
    tshark = tmp_path / "tshark.exe"
    tshark.write_text("", encoding="utf-8")
    write_mcp_json(mcp_json, python_exe=python, tshark_path=tshark)
    data = json.loads(mcp_json.read_text(encoding="utf-8"))
    env = data["mcpServers"]["wireshark"]["env"]
    assert env["TSHARK_PATH"] == str(tshark.resolve())
    assert data["mcpServers"]["wireshark"]["args"] == ["-m", "wireshark_mcp"]


def test_ensure_ready_exits_when_missing(monkeypatch):
    from wireshark_mcp import preflight

    monkeypatch.setattr(
        preflight,
        "run_preflight",
        lambda **_: preflight.PreflightReport(
            ok=False,
            tshark_path=None,
            tshark_version=None,
            npcape_ok=None,
            python_ok=True,
            messages=["TShark NOT FOUND"],
            install_hints=["install tshark"],
        ),
    )
    with pytest.raises(SystemExit) as exc:
        preflight.ensure_ready_or_exit()
    assert exc.value.code == 1
