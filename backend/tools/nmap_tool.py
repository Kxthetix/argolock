"""Nmap tool — port scanning and service/version detection."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from loguru import logger

from app.config import settings
from tools.base_tool import BaseTool


class NmapTool(BaseTool):
    name = "nmap"
    docker_image = settings.nmap_docker_image

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        ports = options.get("ports", "top-1000")
        port_arg = "--top-ports 100" if ports == "top-1000" else f"-p {ports}"

        cmd = [
            "nmap",
            "-sV",           # Service/version detection
            "-T4",           # Aggressive timing
            "--open",        # Only open ports
            "-oX", "-",      # XML output to stdout
        ]
        cmd.extend(port_arg.split())
        cmd.append(target)
        return cmd

    def fallback_run(self, target: str, options: Dict[str, Any]) -> Optional[Tuple[str, str, int]]:
        """Fallback to Python-based async TCP connect scan if nmap is blocked or lacks privileges."""
        logger.warning(f"[nmap] Running Python fallback TCP port scan for target: {target}")
        import socket
        import asyncio

        # Top 100 ports matching nmap top-ports or config
        ports_str = options.get("ports", "top-1000")
        if ports_str == "top-1000" or ports_str == "100":
            ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                1723, 3306, 3389, 5900, 8080, 8443, 80, 443, 22, 21, 23, 25, 53,
                110, 135, 139, 143, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
                8000, 8081, 9000, 9090, 27017, 6379, 5432, 1433, 1521, 5000, 3000
            ]
            # Deduplicate
            ports = list(dict.fromkeys(ports))
        else:
            # Parse custom ports list/range
            ports = []
            for part in ports_str.replace(" ", "").split(","):
                if "-" in part:
                    try:
                        start, end = map(int, part.split("-"))
                        ports.extend(range(start, end + 1))
                    except ValueError:
                        pass
                else:
                    try:
                        ports.append(int(part))
                    except ValueError:
                        pass
            if not ports:
                ports = [80, 443, 22, 8080]

        # Restrict to a maximum of 500 ports for fallback safety
        ports = ports[:500]

        async def scan_port(host: str, port: int, sem: asyncio.Semaphore) -> Optional[int]:
            async with sem:
                try:
                    conn = asyncio.open_connection(host, port)
                    _, writer = await asyncio.wait_for(conn, timeout=1.5)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return port
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        async def run_scan():
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                ip = target

            sem = asyncio.Semaphore(100)
            tasks = [scan_port(ip, p, sem) for p in ports]
            results = await asyncio.gather(*tasks)
            return [r for r in results if r is not None], ip

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    fut = pool.submit(asyncio.run, run_scan())
                    open_ports, ip_addr = fut.result(timeout=60)
            else:
                open_ports, ip_addr = loop.run_until_complete(run_scan())
        except Exception as exc:
            logger.warning(f"[nmap-fallback] scan error: {exc}")
            open_ports, ip_addr = [], target

        # Generate a mock Nmap XML string
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<!DOCTYPE nmaprun>',
            f'<nmaprun scanner="nmap" args="nmap (fallback_run) {target}">',
            f'<host><address addr="{ip_addr}" addrtype="ipv4"/><status state="up"/>',
            '<ports>'
        ]
        
        # Simple helper to get service names for common ports
        common_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
            139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
            993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle",
            1723: "pptp", 3000: "http", 3306: "mysql", 3389: "ms-wbt-server",
            5000: "http", 5432: "postgresql", 5900: "vnc", 6379: "redis",
            8000: "http", 8080: "http-proxy", 8081: "http", 8443: "https-alt",
            9000: "http", 27017: "mongodb"
        }

        for p in open_ports:
            svc_name = common_services.get(p, "unknown")
            xml_lines.append(f'<port protocol="tcp" portid="{p}">')
            xml_lines.append('<state state="open" reason="syn-ack"/>')
            xml_lines.append(f'<service name="{svc_name}" method="table"/>')
            xml_lines.append('</port>')

        xml_lines.extend([
            '</ports>',
            '</host>',
            '<runstats><finished exit="success"/></runstats>',
            '</nmaprun>'
        ])
        
        return "\n".join(xml_lines), "", 0

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        """Parse Nmap XML output into structured findings."""
        hosts = []
        open_ports = []
        services = []
        vulnerabilities = []

        if not stdout.strip():
            return {"hosts": [], "open_ports": [], "services": [], "vulnerabilities": []}

        try:
            root = ET.fromstring(stdout)
        except ET.ParseError as e:
            logger.warning(f"Nmap XML parse error: {e}")
            return {"error": f"XML parse error: {e}", "raw": stdout[:5000]}

        for host_elem in root.findall("host"):
            # Host info
            address_elem = host_elem.find("address")
            addr = address_elem.get("addr", target) if address_elem is not None else target
            status_elem = host_elem.find("status")
            state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"
            hosts.append({"address": addr, "state": state})

            # Ports
            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                port_id = port_elem.get("portid")
                protocol = port_elem.get("protocol", "tcp")
                state_elem = port_elem.find("state")
                port_state = state_elem.get("state", "") if state_elem is not None else ""

                if port_state != "open":
                    continue

                service_elem = port_elem.find("service")
                svc_name = ""
                svc_product = ""
                svc_version = ""
                if service_elem is not None:
                    svc_name = service_elem.get("name", "")
                    svc_product = service_elem.get("product", "")
                    svc_version = service_elem.get("version", "")

                port_info = {
                    "port": int(port_id),
                    "protocol": protocol,
                    "state": port_state,
                    "service": svc_name,
                    "product": svc_product,
                    "version": svc_version,
                    "address": addr,
                }
                open_ports.append(port_info)
                if svc_name:
                    services.append({
                        "endpoint": f"{addr}:{port_id}",
                        "service": svc_name,
                        "product": svc_product,
                        "version": svc_version,
                    })

                # Parse NSE script output for vulnerabilities
                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id", "")
                    script_output = script_elem.get("output", "")

                    if "vuln" in script_id or "CVE" in script_output:
                        vuln = {
                            "script": script_id,
                            "port": int(port_id),
                            "service": svc_name,
                            "output": script_output,
                            "address": addr,
                            "endpoint": f"{addr}:{port_id}",
                        }
                        # Extract CVE IDs
                        cves = re.findall(r"CVE-\d{4}-\d+", script_output)
                        if cves:
                            vuln["cve_ids"] = cves
                        vulnerabilities.append(vuln)

        return {
            "hosts": hosts,
            "open_ports": open_ports,
            "services": services,
            "vulnerabilities": vulnerabilities,
            "total_open_ports": len(open_ports),
        }
