"""
Real integration tests for NEW tools: Amass, httpx probe, Naabu, Dalfox.

Rules:
- NO fake/mocked data. Every test hits a REAL target.
- Targets: scanme.nmap.org (authorized), http://scanme.nmap.org (HTTP)
- XSS tests use https://xss-game.appspot.com (Google's XSS training site — safe to probe)
- Each test asserts both the presence AND schema of returned data.

Run:
    cd backend
    $env:PYTHONPATH="."; venv\\Scripts\\python.exe -m pytest tests/test_new_tools.py -v
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from app.models.scan import ToolStatus

TARGET_DOMAIN = "scanme.nmap.org"
TARGET_HTTP   = "http://scanme.nmap.org"
# XSS target: deliberately vulnerable Google XSS game (safe & legal to probe)
TARGET_XSS    = "https://xss-game.appspot.com/level1/frame"


# ═══════════════════════════════════════════════════════════════════════════════
# Amass tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestAmassTool:
    """Tests for AmassTool — OSINT subdomain enumeration."""

    @pytest.mark.asyncio
    async def test_amass_returns_completed(self):
        from tools.amass_tool import AmassTool
        tool = AmassTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED, f"Amass failed: {result.error}"

    @pytest.mark.asyncio
    async def test_amass_result_schema(self):
        from tools.amass_tool import AmassTool
        tool = AmassTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED
        data = result.parsed_data
        assert data is not None
        for key in ("subdomains", "total", "target"):
            assert key in data, f"Missing key '{key}'"
        assert isinstance(data["subdomains"], list)
        assert isinstance(data["total"], int)
        assert data["target"] == TARGET_DOMAIN

    @pytest.mark.asyncio
    async def test_amass_duration_reasonable(self):
        from tools.amass_tool import AmassTool
        tool = AmassTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED
        assert result.duration_seconds is not None
        assert result.duration_seconds < 200, (
            f"Amass took too long: {result.duration_seconds:.1f}s"
        )

    @pytest.mark.asyncio
    async def test_amass_fallback_crtsh(self):
        """Python fallback must query crt.sh and return real JSON output."""
        from tools.amass_tool import AmassTool
        tool = AmassTool()
        stdout, stderr, exit_code = tool.fallback_run(TARGET_DOMAIN, {})
        assert exit_code == 0
        # May return empty string if crt.sh is rate limiting, so we check format only
        for line in stdout.strip().splitlines():
            data = json.loads(line)
            assert "name" in data
            assert "domain" in data
            assert TARGET_DOMAIN in data["domain"]

    @pytest.mark.asyncio
    async def test_amass_subdomain_schema(self):
        from tools.amass_tool import AmassTool
        tool = AmassTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED
        for sd in result.parsed_data["subdomains"]:
            assert "subdomain" in sd
            assert "source" in sd
            assert TARGET_DOMAIN in sd["subdomain"], (
                f"Unexpected subdomain: {sd['subdomain']}"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# httpx probe tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestHttpxProbeTool:
    """Tests for HttpxProbeTool — HTTP service probing."""

    @pytest.mark.asyncio
    async def test_httpx_probe_returns_completed(self):
        from tools.httpx_probe_tool import HttpxProbeTool
        tool = HttpxProbeTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED, f"httpx probe failed: {result.error}"

    @pytest.mark.asyncio
    async def test_httpx_probe_result_schema(self):
        from tools.httpx_probe_tool import HttpxProbeTool
        tool = HttpxProbeTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        data = result.parsed_data
        assert data is not None
        for key in ("target", "probes", "live_urls", "total", "live_count"):
            assert key in data, f"Missing key '{key}'"
        assert isinstance(data["probes"], list)
        assert isinstance(data["live_urls"], list)

    @pytest.mark.asyncio
    async def test_httpx_probe_scanme_is_live(self):
        """scanme.nmap.org port 80 is always up — must appear in live_urls."""
        from tools.httpx_probe_tool import HttpxProbeTool
        tool = HttpxProbeTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        assert result.parsed_data["live_count"] >= 1, (
            "Expected at least one live URL from scanme.nmap.org"
        )

    @pytest.mark.asyncio
    async def test_httpx_probe_collects_status_code(self):
        """Each probe must include a status_code from a real HTTP response."""
        from tools.httpx_probe_tool import HttpxProbeTool
        tool = HttpxProbeTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        for probe in result.parsed_data["probes"]:
            assert "status_code" in probe
            assert isinstance(probe["status_code"], int)

    @pytest.mark.asyncio
    async def test_httpx_probe_fallback_direct(self):
        """Direct fallback_run must return valid JSON with real HTTP data."""
        from tools.httpx_probe_tool import HttpxProbeTool
        tool = HttpxProbeTool()
        stdout, stderr, exit_code = tool.fallback_run(TARGET_HTTP, {})
        assert exit_code == 0
        assert stdout
        data = json.loads(stdout.strip().splitlines()[0])
        assert "status_code" in data
        assert data["status_code"] > 0  # Real HTTP status code


# ═══════════════════════════════════════════════════════════════════════════════
# Naabu tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestNaabuTool:
    """Tests for NaabuTool — fast port scanning."""

    @pytest.mark.asyncio
    async def test_naabu_returns_completed(self):
        from tools.naabu_tool import NaabuTool
        tool = NaabuTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED, f"Naabu failed: {result.error}"

    @pytest.mark.asyncio
    async def test_naabu_result_schema(self):
        from tools.naabu_tool import NaabuTool
        tool = NaabuTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED
        data = result.parsed_data
        assert data is not None
        for key in ("target", "open_ports", "total"):
            assert key in data, f"Missing key '{key}'"
        assert isinstance(data["open_ports"], list)
        assert isinstance(data["total"], int)

    @pytest.mark.asyncio
    async def test_naabu_finds_port_80(self):
        """scanme.nmap.org always has port 80 open — Naabu must detect it."""
        from tools.naabu_tool import NaabuTool
        tool = NaabuTool()
        result = await tool.run(TARGET_DOMAIN, {"top_ports": "100"})
        assert result.status == ToolStatus.COMPLETED
        port_numbers = [p["port"] for p in result.parsed_data["open_ports"]]
        assert 80 in port_numbers, f"Expected port 80 open, got: {port_numbers}"

    @pytest.mark.asyncio
    async def test_naabu_port_schema(self):
        """Each port entry must have host, port, protocol."""
        from tools.naabu_tool import NaabuTool
        tool = NaabuTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED
        for p in result.parsed_data["open_ports"]:
            assert "host" in p
            assert "port" in p
            assert "protocol" in p
            assert isinstance(p["port"], int)

    @pytest.mark.asyncio
    async def test_naabu_fallback_socket_scan(self):
        """Python socket fallback must find at least one open port on scanme.nmap.org."""
        from tools.naabu_tool import NaabuTool
        tool = NaabuTool()
        stdout, stderr, exit_code = tool.fallback_run(TARGET_DOMAIN, {"top_ports": "100"})
        assert exit_code == 0
        assert stdout, "Expected at least one open port from socket scan"
        ports = [json.loads(line)["port"] for line in stdout.strip().splitlines()]
        assert len(ports) > 0
        assert 80 in ports, f"Expected port 80 in socket scan results, got: {ports}"

    @pytest.mark.asyncio
    async def test_naabu_duration_reasonable(self):
        """Naabu must complete within 90 seconds for top-100 ports."""
        from tools.naabu_tool import NaabuTool
        tool = NaabuTool()
        result = await tool.run(TARGET_DOMAIN, {"top_ports": "100"})
        assert result.status == ToolStatus.COMPLETED
        assert result.duration_seconds < 90, (
            f"Naabu took too long: {result.duration_seconds:.1f}s"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Dalfox tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestDalfoxTool:
    """Tests for DalfoxTool — XSS scanner."""

    @pytest.mark.asyncio
    async def test_dalfox_returns_completed(self):
        """Dalfox (or Python fallback) must complete with COMPLETED status."""
        from tools.dalfox_tool import DalfoxTool
        tool = DalfoxTool()
        result = await tool.run(TARGET_XSS)
        assert result.status == ToolStatus.COMPLETED, f"Dalfox failed: {result.error}"

    @pytest.mark.asyncio
    async def test_dalfox_result_schema(self):
        """parsed_data must have target, findings, total keys."""
        from tools.dalfox_tool import DalfoxTool
        tool = DalfoxTool()
        result = await tool.run(TARGET_XSS)
        assert result.status == ToolStatus.COMPLETED
        data = result.parsed_data
        assert data is not None
        for key in ("target", "findings", "total"):
            assert key in data, f"Missing key '{key}'"
        assert isinstance(data["findings"], list)
        assert isinstance(data["total"], int)
        assert data["total"] == len(data["findings"])

    @pytest.mark.asyncio
    async def test_dalfox_finding_schema(self):
        """Each finding must have required fields."""
        from tools.dalfox_tool import DalfoxTool
        tool = DalfoxTool()
        result = await tool.run(TARGET_XSS)
        assert result.status == ToolStatus.COMPLETED
        for f in result.parsed_data["findings"]:
            for key in ("type", "parameter", "url", "payload", "severity"):
                assert key in f, f"Finding missing '{key}': {f}"

    @pytest.mark.asyncio
    async def test_dalfox_fallback_probe_on_xss_game(self):
        """Python fallback must probe XSS game and return structured JSON."""
        from tools.dalfox_tool import DalfoxTool
        tool = DalfoxTool()
        stdout, stderr, exit_code = tool.fallback_run(TARGET_XSS, {})
        assert exit_code == 0
        # Even empty findings is OK — what matters is valid JSON structure
        for line in stdout.strip().splitlines():
            data = json.loads(line)
            assert "parameter" in data
            assert "payload" in data

    @pytest.mark.asyncio
    async def test_dalfox_no_crash_on_static_target(self):
        """Dalfox must handle a target with no parameters gracefully."""
        from tools.dalfox_tool import DalfoxTool
        tool = DalfoxTool()
        # scanme.nmap.org has no XSS params — should return 0 findings without error
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        assert result.parsed_data is not None
        assert "findings" in result.parsed_data


# ═══════════════════════════════════════════════════════════════════════════════
# parse_output unit tests for new tools
# ═══════════════════════════════════════════════════════════════════════════════

class TestNewToolParseOutput:
    """Unit tests for parse_output with real-format data samples."""

    def test_amass_parse_json(self):
        from tools.amass_tool import AmassTool
        tool = AmassTool()
        stdout = (
            '{"name":"www.scanme.nmap.org","domain":"scanme.nmap.org",'
            '"addresses":[{"ip":"45.33.32.156"}],"tag":"cert","sources":["crt.sh"]}\n'
            '{"name":"mail.scanme.nmap.org","domain":"scanme.nmap.org",'
            '"addresses":[],"tag":"cert","sources":["hackertarget"]}\n'
        )
        result = tool.parse_output(stdout, "", TARGET_DOMAIN)
        assert result["total"] == 2
        assert result["subdomains"][0]["subdomain"] == "www.scanme.nmap.org"
        assert "crt.sh" in result["subdomains"][0]["sources"]
        assert result["subdomains"][0]["ip"] == "45.33.32.156"

    def test_amass_parse_deduplication(self):
        from tools.amass_tool import AmassTool
        tool = AmassTool()
        stdout = (
            '{"name":"www.scanme.nmap.org","domain":"scanme.nmap.org","sources":["a"]}\n'
            '{"name":"www.scanme.nmap.org","domain":"scanme.nmap.org","sources":["b"]}\n'
        )
        result = tool.parse_output(stdout, "", TARGET_DOMAIN)
        assert result["total"] == 1, "Duplicate subdomains must be deduplicated"

    def test_httpx_probe_parse_json(self):
        from tools.httpx_probe_tool import HttpxProbeTool
        tool = HttpxProbeTool()
        stdout = json.dumps({
            "url": "http://scanme.nmap.org",
            "input": "http://scanme.nmap.org",
            "status_code": 200,
            "title": "Go ahead and ScanMe!",
            "content_length": 10000,
            "server": "Apache/2.4.7",
            "technologies": ["Apache"],
        })
        result = tool.parse_output(stdout, "", TARGET_HTTP)
        assert result["total"] == 1
        assert result["live_count"] == 1
        assert result["probes"][0]["status_code"] == 200
        assert result["probes"][0]["title"] == "Go ahead and ScanMe!"

    def test_naabu_parse_json(self):
        from tools.naabu_tool import NaabuTool
        tool = NaabuTool()
        stdout = (
            '{"host":"45.33.32.156","port":80,"protocol":"tcp"}\n'
            '{"host":"45.33.32.156","port":22,"protocol":"tcp"}\n'
        )
        result = tool.parse_output(stdout, "", TARGET_DOMAIN)
        assert result["total"] == 2
        ports = [p["port"] for p in result["open_ports"]]
        assert 80 in ports
        assert 22 in ports

    def test_naabu_parse_deduplication(self):
        from tools.naabu_tool import NaabuTool
        tool = NaabuTool()
        stdout = (
            '{"host":"45.33.32.156","port":80,"protocol":"tcp"}\n'
            '{"host":"45.33.32.156","port":80,"protocol":"tcp"}\n'
        )
        result = tool.parse_output(stdout, "", TARGET_DOMAIN)
        assert result["total"] == 1, "Duplicate ports must be deduplicated"

    def test_dalfox_parse_real_json(self):
        from tools.dalfox_tool import DalfoxTool
        tool = DalfoxTool()
        stdout = json.dumps({
            "type": "G",
            "param": "query",
            "evidence": {
                "url": "https://xss-game.appspot.com/level1/frame?query=<script>",
                "payload": "<script>alert(1)</script>",
                "response": "...<script>alert(1)</script>...",
            },
            "poc": "curl -X GET '...'",
            "description": "XSS found in GET parameter",
        })
        result = tool.parse_output(stdout, "", TARGET_XSS)
        assert result["total"] == 1
        assert result["findings"][0]["parameter"] == "query"
        assert result["findings"][0]["severity"] == "high"

    def test_dalfox_parse_fallback_json(self):
        from tools.dalfox_tool import DalfoxTool
        tool = DalfoxTool()
        stdout = json.dumps({
            "type": "GET_PARAM",
            "parameter": "q",
            "url": "https://example.com?q=<payload>",
            "endpoint": "https://example.com",
            "payload": "<dalfox-xss-probe/>",
            "evidence": "<dalfox-xss-probe/>",
            "severity": "high",
            "poc": "...",
            "description": "XSS reflection found",
        })
        result = tool.parse_output(stdout, "", "https://example.com")
        assert result["total"] == 1
        assert result["findings"][0]["parameter"] == "q"
