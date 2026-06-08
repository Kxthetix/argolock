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
