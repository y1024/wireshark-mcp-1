"""Regression tests for CWE-78 command injection in quick_capture."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from wireshark_mcp import (
    _parse_tshark_interface_line,
    quick_capture,
    validate_capture_interface,
    validate_positive_int,
)
from wireshark_mcp.tshark_runner import TsharkResult


INJECTION_PAYLOADS = [
    'eth0"; id #',
    "Wi-Fi & calc",
    "eth0`id`",
    "eth0 | whoami",
    "eth0$(id)",
    "eth0\nid",
]


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_validate_capture_interface_rejects_metacharacters(payload: str) -> None:
    assert validate_capture_interface(payload) is None


def test_validate_capture_interface_allowlists_exact_match() -> None:
    with patch(
        "wireshark_mcp.security.list_interfaces", return_value=["Wi-Fi", "eth0"]
    ):
        assert validate_capture_interface("Wi-Fi") == "Wi-Fi"
        assert validate_capture_interface("eth0") == "eth0"
        assert validate_capture_interface("not-a-real-iface") is None


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_quick_capture_rejects_injection_without_spawning(payload: str) -> None:
    with (
        patch(
            "wireshark_mcp.security.list_interfaces", return_value=["Wi-Fi", "eth0"]
        ),
        patch("wireshark_mcp.tools.capture.popen_tshark_capture") as popen_cap,
    ):
        result = quick_capture(interface=payload, duration=1, packet_limit=1)

    assert result.startswith("Error: invalid or unauthorized interface")
    popen_cap.assert_not_called()


def test_quick_capture_uses_argv_and_shell_false() -> None:
    fake = TsharkResult(
        returncode=0,
        stdout="1\t192.168.1.1\t1.1.1.1\tDNS\n",
        stderr="",
    )

    with (
        patch(
            "wireshark_mcp.security.list_interfaces", return_value=["Wi-Fi"]
        ),
        patch(
            "wireshark_mcp.tools.capture.popen_tshark_capture", return_value=fake
        ) as popen_cap,
    ):
        result = quick_capture(interface="Wi-Fi", duration=1, packet_limit=3)

    popen_cap.assert_called_once()
    args, kwargs = popen_cap.call_args
    cmd = args[0]
    assert isinstance(cmd, list)
    assert cmd[0] == "-i" or "-i" in cmd
    assert cmd[cmd.index("-i") + 1] == "Wi-Fi"
    assert "Packet Count: 1" in result
    assert "DNS" in result


def test_parse_tshark_interface_line_keeps_nested_parens() -> None:
    line = "4. \\Device\\NPF_{123} (vEthernet (WSL (Hyper-V firewall)))"
    names = _parse_tshark_interface_line(line)
    assert "vEthernet (WSL (Hyper-V firewall))" in names


def test_validate_positive_int_clamps() -> None:
    assert validate_positive_int("5", default=3, minimum=1, maximum=10) == 5
    assert validate_positive_int(9999, default=3, minimum=1, maximum=10) == 10
    assert validate_positive_int("nope", default=3, minimum=1, maximum=10) == 3


def test_quick_capture_errors_when_no_packets() -> None:
    fake = TsharkResult(returncode=0, stdout="", stderr=" Capturing on 'Wi-Fi'")
    with (
        patch(
            "wireshark_mcp.security.list_interfaces", return_value=["Wi-Fi"]
        ),
        patch(
            "wireshark_mcp.tools.capture.popen_tshark_capture", return_value=fake
        ),
    ):
        result = quick_capture(interface="Wi-Fi", duration=1, packet_limit=3)
    assert result.startswith("Error: no packets captured")
    assert "SIMULATED" not in result.upper()
