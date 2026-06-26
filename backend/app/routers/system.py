from __future__ import annotations

import shutil
from typing import Any, Dict, List
import httpx
from fastapi import APIRouter, Depends

from app.config import settings
from app.routers.auth import get_current_user

router = APIRouter()


@router.get("/agents")
async def get_agents_status(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieve configuration and status details for all AI agents."""
    openai_configured = bool(settings.openai_api_key)
    claude_configured = bool(settings.anthropic_api_key)
    ollama_configured = True  # Ollama doesn't require a strict API key in default settings

    active_provider = settings.ai_provider
    provider_configured = False

    if active_provider == "openai":
        active_model = settings.openai_model
        provider_configured = openai_configured
    elif active_provider == "claude":
        active_model = settings.anthropic_model
        provider_configured = claude_configured
    elif active_provider == "ollama":
        active_model = settings.ollama_model
        provider_configured = ollama_configured
    else:
        active_model = "unknown"

    agents = [
        {
            "id": "vulnerability_agent",
            "name": "Vulnerability Agent",
            "role": "Parser & Classifier",
            "description": "Analyzes raw output from scanners (Nuclei, Nmap, Nikto, etc.) and maps them to standard vulnerability titles, CVE references, and OWASP categories.",
            "status": "active" if provider_configured else "inactive",
            "prompt_file": "vulnerability_analysis.txt"
        },
        {
            "id": "remediation_agent",
            "name": "Remediation Agent",
            "role": "Fix Advisor",
            "description": "Formulates customized, step-by-step remediation plans and writes secure coding examples (Python, JS, Java, etc.) to resolve vulnerabilities.",
            "status": "active" if provider_configured else "inactive",
            "prompt_file": "remediation_advice.txt"
        },
        {
            "id": "risk_scoring_agent",
            "name": "Risk Scoring Agent",
            "role": "CVSS Calculator",
            "description": "Evaluates the exploitability and impact of vulnerabilities to assign accurate CVSS scores and threat severity levels.",
            "status": "active" if provider_configured else "inactive",
            "prompt_file": "risk_scoring.txt"
        },
        {
            "id": "report_agent",
            "name": "Report Agent",
            "role": "Executive Summarizer",
            "description": "Generates executive summaries, compiles raw technical details into structured chapters, and calculates overall security postures.",
            "status": "active" if provider_configured else "inactive",
            "prompt_file": "report_generation.txt"
        }
    ]

    return {
        "active_provider": active_provider,
        "active_model": active_model,
        "provider_configured": provider_configured,
        "openai_configured": openai_configured,
        "claude_configured": claude_configured,
        "ollama_configured": ollama_configured,
        "agents": agents
    }


@router.get("/tools")
async def get_tools_status(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieve installation status, execution mode, and capability metadata for security tools."""
    tools = [
        {
            "id": "subfinder",
            "name": "Subfinder",
            "phase": "Reconnaissance",
            "description": "Discovers active subdomains using passive OSINT sources.",
            "binary": "subfinder",
            "fallback_implemented": False,
            "docker_image": settings.subfinder_docker_image,
        },
        {
            "id": "amass",
            "name": "Amass",
            "phase": "Reconnaissance",
            "description": "Performs DNS mapping and OSINT-based subdomain enumeration.",
            "binary": "amass",
            "fallback_implemented": False,
            "docker_image": None,
        },
        {
            "id": "naabu",
            "name": "Naabu",
            "phase": "Reconnaissance",
            "description": "Fast port scanner using TCP/UDP SYN probes.",
            "binary": "naabu",
            "fallback_implemented": True,
            "docker_image": None,
        },
        {
            "id": "nmap",
            "name": "Nmap",
            "phase": "Reconnaissance",
            "description": "Standard port scanner, service detection, and scripting engine.",
            "binary": "nmap",
            "fallback_implemented": True,
            "docker_image": settings.nmap_docker_image,
        },
        {
            "id": "httpx_probe",
            "name": "httpx-probe",
            "phase": "Reconnaissance",
            "description": "HTTP probing tool to identify web technologies, titles, and live endpoints.",
            "binary": "httpx",
            "fallback_implemented": True,
            "docker_image": None,
        },
        {
            "id": "whatweb",
            "name": "WhatWeb",
            "phase": "Reconnaissance",
            "description": "Technology fingerprinting of content management systems, plugins, and servers.",
            "binary": "whatweb",
            "fallback_implemented": False,
            "docker_image": None,
        },
        {
            "id": "nuclei",
            "name": "Nuclei",
            "phase": "Vulnerability Scanning",
            "description": "Fast, template-based vulnerability scanner for web targets.",
            "binary": "nuclei",
            "fallback_implemented": False,
            "docker_image": settings.nuclei_docker_image,
        },
        {
            "id": "nikto",
            "name": "Nikto",
            "phase": "Vulnerability Scanning",
            "description": "Scans web servers for outdated software, common misconfigurations, and dangerous paths.",
            "binary": "nikto",
            "fallback_implemented": True,
            "docker_image": settings.nikto_docker_image,
        },
        {
            "id": "dalfox",
            "name": "Dalfox",
            "phase": "Vulnerability Scanning",
            "description": "Detects Cross-Site Scripting (XSS) vulnerabilities via active injection.",
            "binary": "dalfox",
            "fallback_implemented": False,
            "docker_image": None,
        },
        {
            "id": "zap",
            "name": "OWASP ZAP",
            "phase": "Vulnerability Scanning",
            "description": "Orchestrates active and passive vulnerability analysis using OWASP ZAP API.",
            "binary": "zap-api",
            "fallback_implemented": True,
            "docker_image": None,
        },
        {
            "id": "sqlmap",
            "name": "SQLmap",
            "phase": "Exploitation",
            "description": "Automated SQL injection detection and database takeover tool.",
            "binary": "sqlmap",
            "fallback_implemented": False,
            "docker_image": settings.sqlmap_docker_image,
        }
    ]

    execution_mode = settings.tool_execution_mode
    results = []

    for tool in tools:
        binary_path = None
        is_installed = False

        if tool["id"] == "zap":
            try:
                async with httpx.AsyncClient(timeout=1.5) as client:
                    resp = await client.get(settings.zap_base_url)
                    is_installed = resp.status_code < 500
                    binary_path = settings.zap_base_url
            except Exception:
                is_installed = False
        else:
            binary_name = tool["binary"]
            found_path = shutil.which(binary_name)
            if found_path:
                is_installed = True
                binary_path = found_path

        # Determine status classification
        if is_installed:
            status = "available"
        elif execution_mode == "docker" and tool["docker_image"]:
            status = "available"  # Available via container running
        elif tool["fallback_implemented"]:
            status = "fallback"
        else:
            status = "missing"

        results.append({
            "id": tool["id"],
            "name": tool["name"],
            "phase": tool["phase"],
            "description": tool["description"],
            "binary": tool["binary"],
            "execution_mode": "docker" if (execution_mode == "docker" and tool["docker_image"]) else "subprocess",
            "docker_image": tool["docker_image"],
            "status": status,
            "binary_path": binary_path,
            "fallback_implemented": tool["fallback_implemented"]
        })

    return {
        "execution_mode": execution_mode,
        "tools": results
    }
