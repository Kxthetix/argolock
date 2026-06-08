"""Naabu tool — fast port scanning by ProjectDiscovery.

Naabu is significantly faster than Nmap for host discovery / port enumeration.
It focuses on SYN / CONNECT scanning. When the binary is missing, falls back
to a real Python asyncio socket-based port scanner.
"""
from __future__ import annotations

import asyncio
import json
import socket
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from tools.base_tool import BaseTool


class NaabuTool(BaseTool):
    name = "naabu"
    docker_image = None

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        top_ports = options.get("top_ports", "1000")
        rate      = options.get("rate", 500)
        return [
            "naabu",
            "-host", target,
            "-top-ports", str(top_ports),
            "-silent",
            "-json",
            "-rate", str(rate),
            "-timeout", "5",        # ms per port connect attempt
            "-no-color",
            "-exclude-cdn",         # Skip full scan for CDN IPs
        ]

    # ── Python fallback ───────────────────────────────────────────────────────

    def fallback_run(self, target: str, options: Dict[str, Any]) -> Tuple[str, str, int]:
        """Real asyncio socket scanner — probes common ports concurrently."""
        logger.info(f"[naabu] Running Python async socket port scanner on {target}")

        # Top-100 most common ports
        TOP_100 = [
            21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 443, 445,
            465, 514, 587, 631, 993, 995, 1025, 1080, 1194, 1433, 1521, 1723,
            2049, 2082, 2083, 2086, 2087, 2095, 2096, 2483, 2484, 3000, 3306,
            3389, 3690, 4000, 4444, 4567, 4848, 5000, 5001, 5432, 5900, 5938,
            6000, 6001, 6379, 6443, 7001, 7002, 7077, 7443, 7474, 8000, 8001,
            8008, 8009, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
            8089, 8090, 8161, 8443, 8444, 8880, 8888, 8983, 9000, 9001, 9090,
            9092, 9200, 9300, 9418, 9443, 10000, 10250, 10443, 11211, 27017,
            27018, 28017, 50000, 50070, 61616,
        ]

        top_n = int(options.get("top_ports", "100"))
        ports = TOP_100[:top_n] if top_n <= len(TOP_100) else TOP_100

        async def scan_port(host: str, port: int, sem: asyncio.Semaphore) -> Optional[dict]:
            async with sem:
                try:
                    conn = asyncio.open_connection(host, port)
                    _, writer = await asyncio.wait_for(conn, timeout=1.5)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return {"host": host, "port": port, "protocol": "tcp"}
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        async def run_scan():
            # Resolve hostname once
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                ip = target

            sem = asyncio.Semaphore(100)  # max 100 concurrent
            tasks = [scan_port(ip, p, sem) for p in ports]
            results = await asyncio.gather(*tasks)
            open_ports = [r for r in results if r is not None]
            # Add hostname to each result
            for r in open_ports:
                r["hostname"] = target
            return open_ports

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    fut = pool.submit(asyncio.run, run_scan())
                    open_ports = fut.result(timeout=60)
            else:
                open_ports = loop.run_until_complete(run_scan())
        except Exception as exc:
            logger.warning(f"[naabu-fallback] scan error: {exc}")
            open_ports = []

        stdout = "\n".join(json.dumps(p) for p in open_ports)
        return stdout, "", 0

    # ── Parse output ──────────────────────────────────────────────────────────

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        ports = []
        seen = set()

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", data.get("hostname", target))
                port = data.get("port", 0)
                proto = data.get("protocol", "tcp")
                key = (host, port, proto)
                if key not in seen:
                    seen.add(key)
                    ports.append({
                        "host": host,
                        "port": port,
                        "protocol": proto,
                    })
            except json.JSONDecodeError:
                # "host:port" plain text fallback
                if ":" in line:
                    parts = line.rsplit(":", 1)
                    try:
                        port = int(parts[1])
                        host = parts[0]
                        key = (host, port, "tcp")
                        if key not in seen:
                            seen.add(key)
                            ports.append({"host": host, "port": port, "protocol": "tcp"})
                    except ValueError:
                        pass

        return {
            "target": target,
            "open_ports": ports,
            "total": len(ports),
        }
