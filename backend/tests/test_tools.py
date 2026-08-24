"""
Real integration tests for all VAPT tool wrappers.

Rules:
- NO fake/mocked data. Every test hits a real target.
- Target: scanme.nmap.org (Nmap's publicly authorized test host, safe to scan).
- HTTP target: http://scanme.nmap.org (HTTP fingerprinting / web scans).
- Each test asserts the shape AND reality of the returned data.

Run with:
    cd backend
    $env:PYTHONPATH="."; venv\\Scripts\\python.exe -m pytest tests/test_tools.py -v
"""
from __future__ import annotations

import asyncio
import sys
import os
import json

# Ensure backend is in sys.path when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import pytest_asyncio

from app.models.scan import ToolStatus

# ── Target constants ─────────────────────────────────────────────────────────
TARGET_DOMAIN = "scanme.nmap.org"
TARGET_HTTP   = "http://scanme.nmap.org"


# ═══════════════════════════════════════════════════════════════════════════════
# Subfinder tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestSubfinderTool:
    """Tests for SubfinderTool — real subdomain enumeration."""

    @pytest.mark.asyncio
    async def test_subfinder_returns_completed(self):
        """Subfinder must complete (not timeout/fail) within the timeout window."""
        from tools.subfinder_tool import SubfinderTool
        tool = SubfinderTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED, (
            f"Subfinder failed with: {result.error}"
        )

    @pytest.mark.asyncio
    async def test_subfinder_result_schema(self):
        """parsed_data must contain 'subdomains', 'total', 'target' keys."""
        from tools.subfinder_tool import SubfinderTool
        tool = SubfinderTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED
        data = result.parsed_data
        assert data is not None
        assert "subdomains" in data
        assert "total" in data
        assert "target" in data
        assert data["target"] == TARGET_DOMAIN
        assert isinstance(data["subdomains"], list)
        assert isinstance(data["total"], int)
        assert data["total"] >= 0

    @pytest.mark.asyncio
    async def test_subfinder_subdomain_schema(self):
        """Each subdomain entry must have 'subdomain' and 'source' keys."""
        from tools.subfinder_tool import SubfinderTool
        tool = SubfinderTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED
        for sd in result.parsed_data["subdomains"]:
            assert "subdomain" in sd, f"Missing 'subdomain' key in: {sd}"
            assert "source" in sd,    f"Missing 'source' key in: {sd}"
            assert TARGET_DOMAIN in sd["subdomain"], (
                f"Subdomain '{sd['subdomain']}' does not belong to {TARGET_DOMAIN}"
            )

    @pytest.mark.asyncio
    async def test_subfinder_duration_reasonable(self):
        """Subfinder must complete in less than 180 seconds (3 min max)."""
        from tools.subfinder_tool import SubfinderTool
        tool = SubfinderTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.duration_seconds is not None
        assert result.duration_seconds < 180, (
            f"Subfinder took too long: {result.duration_seconds:.1f}s"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Nmap tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestNmapTool:
    """Tests for NmapTool — real port scanning."""

    @pytest.mark.asyncio
    async def test_nmap_returns_completed(self):
        """Nmap must complete successfully."""
        from tools.nmap_tool import NmapTool
        tool = NmapTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED, (
            f"Nmap failed with: {result.error}"
        )

    @pytest.mark.asyncio
    async def test_nmap_result_schema(self):
        """parsed_data must have hosts, open_ports, services, vulnerabilities keys."""
        from tools.nmap_tool import NmapTool
        tool = NmapTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED
        data = result.parsed_data
        assert data is not None
        for key in ("hosts", "open_ports", "services", "total_open_ports"):
            assert key in data, f"Missing key '{key}' in Nmap result"
        assert isinstance(data["open_ports"], list)
        assert isinstance(data["hosts"], list)

    @pytest.mark.asyncio
    async def test_nmap_finds_open_ports(self):
        """scanme.nmap.org is guaranteed to have open ports (22, 80)."""
        from tools.nmap_tool import NmapTool
        tool = NmapTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED
        open_ports = result.parsed_data.get("open_ports", [])
        assert len(open_ports) > 0, "Expected at least one open port on scanme.nmap.org"
        port_numbers = [p["port"] for p in open_ports]
        # scanme.nmap.org is well known to have port 80 open
        assert 80 in port_numbers, f"Expected port 80 open, got: {port_numbers}"

    @pytest.mark.asyncio
    async def test_nmap_port_schema(self):
        """Each port entry must have port, protocol, state, service fields."""
        from tools.nmap_tool import NmapTool
        tool = NmapTool()
        result = await tool.run(TARGET_DOMAIN)
        assert result.status == ToolStatus.COMPLETED
        for port in result.parsed_data.get("open_ports", []):
            for key in ("port", "protocol", "state", "service"):
                assert key in port, f"Port entry missing key '{key}': {port}"
            assert port["state"] == "open"
            assert isinstance(port["port"], int)


# ═══════════════════════════════════════════════════════════════════════════════
# WhatWeb tests (with Python fallback)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWhatWebTool:
    """Tests for WhatWebTool — real HTTP technology fingerprinting."""

    @pytest.mark.asyncio
    async def test_whatweb_returns_completed(self):
        """WhatWeb (or Python fallback) must complete successfully."""
        from tools.whatweb_tool import WhatWebTool
        tool = WhatWebTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED, (
            f"WhatWeb failed with: {result.error}"
        )

    @pytest.mark.asyncio
    async def test_whatweb_result_schema(self):
        """parsed_data must have target, technologies, headers, server_info."""
        from tools.whatweb_tool import WhatWebTool
        tool = WhatWebTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        data = result.parsed_data
        assert data is not None
        for key in ("target", "technologies", "headers", "server_info"):
            assert key in data, f"Missing key '{key}' in WhatWeb result"
        assert isinstance(data["technologies"], list)

    @pytest.mark.asyncio
    async def test_whatweb_finds_real_technologies(self):
        """scanme.nmap.org must return at least one technology fingerprint."""
        from tools.whatweb_tool import WhatWebTool
        tool = WhatWebTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        techs = result.parsed_data.get("technologies", [])
        assert len(techs) > 0, (
            "Expected at least one technology fingerprint from scanme.nmap.org"
        )
        # Check schema of each tech entry
        for tech in techs:
            assert "name" in tech, f"Technology entry missing 'name': {tech}"

    @pytest.mark.asyncio
    async def test_whatweb_fallback_probe(self):
        """Directly test the Python fallback_run against a live target."""
        from tools.whatweb_tool import WhatWebTool
        tool = WhatWebTool()
        stdout, stderr, exit_code = tool.fallback_run(TARGET_HTTP, {})
        assert exit_code == 0
        assert stdout  # Should not be empty
        parsed = json.loads(stdout)
        assert isinstance(parsed, list)
        assert len(parsed) > 0
        # Must have a plugins dict
        assert "plugins" in parsed[0]
        # Must contain at least a Status key
        assert "Status" in parsed[0]["plugins"], (
            f"Expected 'Status' in plugins, got: {list(parsed[0]['plugins'].keys())}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Nuclei tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestNucleiTool:
    """Tests for NucleiTool — real template-based vulnerability scanning."""

    @pytest.mark.asyncio
    async def test_nuclei_returns_completed(self):
        """Nuclei must complete successfully."""
        from tools.nuclei_tool import NucleiTool
        tool = NucleiTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED, (
            f"Nuclei failed with: {result.error}"
        )

    @pytest.mark.asyncio
    async def test_nuclei_result_schema(self):
        """parsed_data must have findings and total keys."""
        from tools.nuclei_tool import NucleiTool
        tool = NucleiTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        data = result.parsed_data
        assert data is not None
        assert "findings" in data
        assert "total" in data
        assert isinstance(data["findings"], list)
        assert isinstance(data["total"], int)
        assert data["total"] == len(data["findings"])

    @pytest.mark.asyncio
    async def test_nuclei_finding_schema(self):
        """Each Nuclei finding must have required fields."""
        from tools.nuclei_tool import NucleiTool
        tool = NucleiTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        for finding in result.parsed_data.get("findings", []):
            for key in ("template_id", "severity", "matched_at", "host"):
                assert key in finding, f"Finding missing key '{key}': {finding}"
            assert finding["severity"] in (
                "critical", "high", "medium", "low", "info", "unknown"
            ), f"Unexpected severity: {finding['severity']}"


# ═══════════════════════════════════════════════════════════════════════════════
# Nikto tests (with Python fallback)
# ═══════════════════════════════════════════════════════════════════════════════

class TestNiktoTool:
    """Tests for NiktoTool — real web server security scanning."""

    @pytest.mark.asyncio
    async def test_nikto_returns_completed(self):
        """Nikto (or Python fallback) must complete successfully."""
        from tools.nikto_tool import NiktoTool
        tool = NiktoTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED, (
            f"Nikto failed with: {result.error}"
        )

    @pytest.mark.asyncio
    async def test_nikto_result_schema(self):
        """parsed_data must have findings, total, target keys."""
        from tools.nikto_tool import NiktoTool
        tool = NiktoTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        data = result.parsed_data
        assert data is not None
        for key in ("findings", "total", "target"):
            assert key in data, f"Missing key '{key}' in Nikto result"
        assert isinstance(data["findings"], list)
        assert data["total"] == len(data["findings"])

    @pytest.mark.asyncio
    async def test_nikto_finds_real_issues(self):
        """scanme.nmap.org must produce at least one security finding."""
        from tools.nikto_tool import NiktoTool
        tool = NiktoTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        findings = result.parsed_data.get("findings", [])
        assert len(findings) > 0, (
            "Expected at least one security finding from scanme.nmap.org (missing headers, etc)"
        )

    @pytest.mark.asyncio
    async def test_nikto_finding_schema(self):
        """Each Nikto finding must have id, msg, url, method fields."""
        from tools.nikto_tool import NiktoTool
        tool = NiktoTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        for finding in result.parsed_data.get("findings", []):
            assert "msg" in finding, f"Finding missing 'msg': {finding}"
            assert "url" in finding or "endpoint" in finding, (
                f"Finding missing url/endpoint: {finding}"
            )

    @pytest.mark.asyncio
    async def test_nikto_fallback_direct(self):
        """Directly test fallback_run returns valid JSON with real security findings."""
        from tools.nikto_tool import NiktoTool
        tool = NiktoTool()
        stdout, stderr, exit_code = tool.fallback_run(TARGET_HTTP, {})
        assert exit_code == 0
        data = json.loads(stdout)
        assert "vulnerabilities" in data
        assert isinstance(data["vulnerabilities"], list)
        # Must have at least one finding (missing CSP/XFO on scanme.nmap.org)
        assert len(data["vulnerabilities"]) > 0, (
            "Expected at least one finding from Python fallback on scanme.nmap.org"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# ZAP tests (with Python fallback)
# ═══════════════════════════════════════════════════════════════════════════════

class TestZAPTool:
    """Tests for ZAPTool — security scanning with Python fallback when ZAP API offline."""

    @pytest.mark.asyncio
    async def test_zap_returns_completed(self):
        """ZAP (or Python fallback) must complete with COMPLETED status."""
        from tools.zap_tool import ZAPTool
        tool = ZAPTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED, (
            f"ZAP returned FAILED: {result.error}"
        )

    @pytest.mark.asyncio
    async def test_zap_result_schema(self):
        """parsed_data must have findings, total, target keys."""
        from tools.zap_tool import ZAPTool
        tool = ZAPTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        data = result.parsed_data
        assert data is not None
        for key in ("findings", "total", "target"):
            assert key in data, f"Missing key '{key}' in ZAP result"
        assert isinstance(data["findings"], list)
        assert data["total"] == len(data["findings"])
        assert data["target"] == TARGET_HTTP

    @pytest.mark.asyncio
    async def test_zap_finds_real_issues(self):
        """ZAP or Python fallback must find at least one real security issue."""
        from tools.zap_tool import ZAPTool
        tool = ZAPTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        findings = result.parsed_data.get("findings", [])
        assert len(findings) > 0, (
            "Expected at least one finding from scanme.nmap.org (e.g. missing security headers)"
        )

    @pytest.mark.asyncio
    async def test_zap_finding_schema(self):
        """Each ZAP finding must have name, severity, description, url fields."""
        from tools.zap_tool import ZAPTool
        tool = ZAPTool()
        result = await tool.run(TARGET_HTTP)
        assert result.status == ToolStatus.COMPLETED
        for finding in result.parsed_data.get("findings", []):
            for key in ("name", "severity", "description", "url"):
                assert key in finding, f"Finding missing key '{key}': {finding}"

    @pytest.mark.asyncio
    async def test_zap_python_fallback_cors(self):
        """Python fallback must probe CORS and return result."""
        from tools.zap_tool import ZAPTool
        tool = ZAPTool()
        # Run fallback directly
        data, _ = await tool._python_fallback_scan(TARGET_HTTP)
        assert "findings" in data
        assert "total" in data
        assert "target" in data
        assert data["target"] == TARGET_HTTP
        assert isinstance(data["findings"], list)

    @pytest.mark.asyncio
    async def test_zap_python_fallback_clickjacking(self):
        """Python fallback must detect missing X-Frame-Options on scanme.nmap.org."""
        from tools.zap_tool import ZAPTool
        tool = ZAPTool()
        data, _ = await tool._python_fallback_scan(TARGET_HTTP)
        finding_names = [f["name"] for f in data["findings"]]
        # scanme.nmap.org almost certainly lacks X-Frame-Options
        assert any(
            "clickjacking" in n.lower() or "frame" in n.lower() or "csp" in n.lower()
            for n in finding_names
        ), f"Expected a Clickjacking or CSP finding but got: {finding_names}"


# ═══════════════════════════════════════════════════════════════════════════════
# parse_output unit tests (real output samples)
# ═══════════════════════════════════════════════════════════════════════════════

class TestParseOutputUnits:
    """Unit tests for each tool's parse_output using real data samples."""

    def test_nmap_parse_valid_xml(self):
        """parse_output must handle valid Nmap XML with open port."""
        from tools.nmap_tool import NmapTool
        tool = NmapTool()
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.7"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        result = tool.parse_output(xml, "", "scanme.nmap.org")
        assert result["total_open_ports"] == 1
        assert result["open_ports"][0]["port"] == 80
        assert result["open_ports"][0]["service"] == "http"

    def test_nmap_parse_empty_output(self):
        """parse_output must return empty structure on empty stdout."""
        from tools.nmap_tool import NmapTool
        tool = NmapTool()
        result = tool.parse_output("", "", "target")
        assert result["open_ports"] == []
        assert result["hosts"] == []

    def test_subfinder_parse_json_lines(self):
        """parse_output must correctly parse JSONL subfinder output."""
        from tools.subfinder_tool import SubfinderTool
        tool = SubfinderTool()
        stdout = (
            '{"host":"www.scanme.nmap.org","source":"crtsh","ip":""}\n'
            '{"host":"mail.scanme.nmap.org","source":"hackertarget","ip":"45.33.32.156"}\n'
        )
        result = tool.parse_output(stdout, "", "scanme.nmap.org")
        assert result["total"] == 2
        assert result["subdomains"][0]["subdomain"] == "www.scanme.nmap.org"
        assert result["subdomains"][1]["source"] == "hackertarget"

    def test_subfinder_parse_plain_text_fallback(self):
        """parse_output must handle plain text (non-JSON) subfinder output."""
        from tools.subfinder_tool import SubfinderTool
        tool = SubfinderTool()
        stdout = "sub1.scanme.nmap.org\nsub2.scanme.nmap.org\n"
        result = tool.parse_output(stdout, "", "scanme.nmap.org")
        assert result["total"] == 2
        assert result["subdomains"][0]["subdomain"] == "sub1.scanme.nmap.org"

    def test_whatweb_parse_output(self):
        """parse_output must correctly extract technologies from WhatWeb JSON."""
        from tools.whatweb_tool import WhatWebTool
        tool = WhatWebTool()
        stdout = json.dumps([{
            "target": "http://example.com",
            "plugins": {
                "HTTPServer": {"string": ["Apache/2.4.7"]},
                "PHP": {"version": ["7.4.3"]},
                "X-Powered-By": {"string": ["PHP/7.4.3"]},
            }
        }])
        result = tool.parse_output(stdout, "", "http://example.com")
        assert result["target"] == "http://example.com"
        tech_names = [t["name"] for t in result["technologies"]]
        assert "HTTPServer" in tech_names
        assert "PHP" in tech_names
        assert result["server_info"].get("server") == "Apache/2.4.7"

    def test_nikto_parse_json_output(self):
        """parse_output must correctly parse Nikto-format JSON."""
        from tools.nikto_tool import NiktoTool
        tool = NiktoTool()
        stdout = json.dumps({"vulnerabilities": [
            {
                "id": "HDR-001",
                "method": "GET",
                "url": "http://example.com",
                "msg": "Missing X-Frame-Options",
                "severity": "high",
                "references": {"url": []},
            }
        ]})
        result = tool.parse_output(stdout, "", "http://example.com")
        assert result["total"] == 1
        assert result["findings"][0]["msg"] == "Missing X-Frame-Options"
        assert result["findings"][0]["severity"] == "high"

    def test_nuclei_parse_jsonl(self):
        """parse_output must parse Nuclei JSONL output into structured findings."""
        from tools.nuclei_tool import NucleiTool
        tool = NucleiTool()
        line = json.dumps({
            "template-id": "http-missing-security-headers",
            "info": {
                "name": "HTTP Missing Security Headers",
                "severity": "info",
                "description": "Missing security headers detected.",
                "tags": ["headers", "generic"],
                "classification": {"cvss-score": 0.0},
            },
            "matched-at": "http://scanme.nmap.org",
            "host": "scanme.nmap.org",
            "type": "http",
        })
        result = tool.parse_output(line, "", "http://scanme.nmap.org")
        assert result["total"] == 1
        assert result["findings"][0]["template_id"] == "http-missing-security-headers"
        assert result["findings"][0]["severity"] == "info"
