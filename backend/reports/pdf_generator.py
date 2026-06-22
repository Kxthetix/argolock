"""PDF report generator using Jinja2 + WeasyPrint."""
from __future__ import annotations

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader
from loguru import logger

from app.config import settings


def enrich_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure finding has category, source, confidence, evidence, remediation and compliance."""
    title = f.get("title", "")
    description = f.get("description", "")
    
    # Set default metadata
    f["category"] = f.get("category") or f.get("owasp_category") or "web"
    if f["category"] == "Unknown":
        f["category"] = "web"
    f["source"] = f.get("tool_source") or "scanner"
    f["confidence"] = f.get("confidence") or "medium"
    f["evidence"] = f.get("evidence") or f.get("affected_endpoint") or "N/A"
    
    # Generate remediation if missing
    if "remediation" not in f or not f.get("remediation"):
        rem = {
            "root_cause": "The service or configuration lacks security controls or headers, allowing potential abuse.",
            "fix_steps": [
                "Review the system configuration settings.",
                "Apply the recommended security header or configuration option.",
                "Verify and test that the changes do not affect system operations."
            ],
            "secure_code_example": "N/A",
            "references": []
        }
        
        title_lower = title.lower()
        desc_lower = description.lower()
        if "sql" in title_lower or "sqlmap" in title_lower or "injection" in title_lower:
            rem["root_cause"] = "Direct concatenation of user-supplied input into database query strings allows attackers to execute arbitrary SQL commands."
            rem["fix_steps"] = [
                "Use parameterized queries (prepared statements) for all database operations.",
                "Implement input validation and data sanitization using a whitelist approach.",
                "Ensure database user permissions are restricted to the minimum required privilege level."
            ]
            rem["secure_code_example"] = """# SECURE: Use prepared statements
query = "SELECT * FROM users WHERE username = %s AND password = %s"
cursor.execute(query, (username, password))"""
            f["owasp_category"] = "A03:2021 - Injection"
            f["confidence"] = "high"
            
        elif "x-frame-options" in title_lower or "clickjacking" in title_lower:
            rem["root_cause"] = "The 'X-Frame-Options' header is not configured on the web server, allowing malicious sites to embed this page inside an iframe and perform clickjacking attacks."
            rem["fix_steps"] = [
                "Configure your web server to return the 'X-Frame-Options: SAMEORIGIN' HTTP response header.",
                "Alternatively, configure Content-Security-Policy with 'frame-ancestors \\'self\\'' directive."
            ]
            rem["secure_code_example"] = """# Apache configuration
Header always set X-Frame-Options "SAMEORIGIN"

# Nginx configuration
add_header X-Frame-Options "SAMEORIGIN" always;"""
            f["owasp_category"] = "A05:2021 - Security Misconfiguration"
            f["confidence"] = "medium"
            
        elif "content-security-policy" in title_lower or "csp" in title_lower:
            rem["root_cause"] = "The 'Content-Security-Policy' (CSP) header is missing or poorly configured, weakening defenses against Cross-Site Scripting (XSS) and code injection attacks."
            rem["fix_steps"] = [
                "Define a robust Content-Security-Policy header policy.",
                "Deploy the header using 'Content-Security-Policy: default-src \\'self\\'; script-src \\'self\\'; object-src \\'none\\';'."
            ]
            rem["secure_code_example"] = """# Nginx configuration
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; frame-ancestors 'self';" always;"""
            f["owasp_category"] = "A05:2021 - Security Misconfiguration"
            f["confidence"] = "medium"
            
        elif "x-content-type-options" in title_lower or "mime-sniffing" in title_lower:
            rem["root_cause"] = "The 'X-Content-Type-Options' header is not set to 'nosniff', which can lead browsers to parse files as a different MIME type, enabling cross-site scripting."
            rem["fix_steps"] = [
                "Add the HTTP response header 'X-Content-Type-Options: nosniff' to all responses."
            ]
            rem["secure_code_example"] = """# Nginx configuration
add_header X-Content-Type-Options "nosniff" always;"""
            f["owasp_category"] = "A05:2021 - Security Misconfiguration"
            f["confidence"] = "medium"
            
        elif "x-xss-protection" in title_lower:
            rem["root_cause"] = "The legacy 'X-XSS-Protection' header is missing or improperly configured, which disables the built-in XSS filters in older web browsers."
            rem["fix_steps"] = [
                "Set the 'X-XSS-Protection' header to '1; mode=block' to prevent page rendering when XSS is detected."
            ]
            rem["secure_code_example"] = """# Nginx configuration
add_header X-XSS-Protection "1; mode=block" always;"""
            f["owasp_category"] = "A05:2021 - Security Misconfiguration"
            f["confidence"] = "medium"

        elif "referrer-policy" in title_lower:
            rem["root_cause"] = "Referrer-Policy header is missing, causing sensitive URL query parameters to be leaked to external sites via the Referer header."
            rem["fix_steps"] = [
                "Configure a secure Referrer-Policy header such as 'strict-origin-when-cross-origin' or 'no-referrer'."
            ]
            rem["secure_code_example"] = """# Nginx configuration
add_header Referrer-Policy "strict-origin-when-cross-origin" always;"""
            f["owasp_category"] = "A05:2021 - Security Misconfiguration"
            f["confidence"] = "medium"
            
        f["remediation"] = rem
        
    # Standardize compliance_owasp list
    ow = f.get("owasp_category") or "Unknown"
    if not ow or ow == "Unknown":
        ow = "A05:2021 - Security Misconfiguration"
    f["compliance_owasp"] = [ow]
    return f


async def generate_pdf(report_data: Dict[str, Any], scan_id: str) -> str:
    """Render HTML template and convert to PDF."""
    try:
        import weasyprint
    except (ImportError, OSError) as e:
        logger.warning(f"WeasyPrint not installed/importable locally: {e}. PDF generation will write HTML instead.")
        weasyprint = None

    # Fetch scan document for full tool results and asset details
    scan_doc = None
    try:
        from workers.recon_worker import _get_db_sync
        db = _get_db_sync()
        scan_doc = db["scans"].find_one({"id": scan_id})
    except Exception as e:
        logger.warning(f"Could not retrieve scan_doc synchronously: {e}")

    # 1. Target & Stats
    target = report_data.get("target") or (scan_doc.get("scope", {}).get("target") if scan_doc else "unknown")
    status = scan_doc.get("status") or "completed" if scan_doc else "completed"
    scan_type = "full" if (scan_doc and scan_doc.get("config", {}).get("enable_exploitation")) else "recon"
    
    findings = report_data.get("findings") or []
    # If findings list is empty in report_data, query from DB findings collection
    if not findings and scan_id:
        try:
            from workers.recon_worker import _get_db_sync
            db = _get_db_sync()
            findings = list(db["findings"].find({"scan_id": scan_id}))
        except Exception as e:
            logger.warning(f"Could not load findings from DB: {e}")
            
    # Enrich findings with category, source, confidence, evidence, remediation and compliance
    enriched_findings = [enrich_finding(dict(f)) for f in findings]
    
    # Recalculate statistics
    stats = report_data.get("statistics") or {}
    total_findings = len(enriched_findings)
    critical_cnt = sum(1 for f in enriched_findings if f.get("severity") == "critical")
    high_cnt = sum(1 for f in enriched_findings if f.get("severity") == "high")
    medium_cnt = sum(1 for f in enriched_findings if f.get("severity") == "medium")
    low_cnt = sum(1 for f in enriched_findings if f.get("severity") == "low")
    info_cnt = sum(1 for f in enriched_findings if f.get("severity") == "info")
    
    overall_score = report_data.get("risk_score") or 0.0
    overall_rating = (report_data.get("risk_rating") or "Low").upper()

    # 2. Asset Inventory Data
    subdomains_list = []
    ports_list = []
    http_probes = []
    
    if scan_doc:
        tr = scan_doc.get("tool_results", {})
        # Subdomains
        for tool in ["subfinder", "amass"]:
            tool_data = tr.get(tool, {})
            if tool_data and tool_data.get("status") == "completed":
                subdomains_list.extend(tool_data.get("parsed_data", {}).get("subdomains", []))
        
        # Open Ports
        for tool in ["naabu", "nmap"]:
            tool_data = tr.get(tool, {})
            if tool_data and tool_data.get("status") == "completed":
                ports_list.extend(tool_data.get("parsed_data", {}).get("open_ports", []))
                
        # HTTP Services
        httpx_data = tr.get("httpx_probe", {})
        if httpx_data and httpx_data.get("status") == "completed":
            http_probes.extend(httpx_data.get("parsed_data", {}).get("probes", []))

    # Process Subdomains
    unique_subdomains = list(set(s.get("subdomain") or s.get("host") for s in subdomains_list if s.get("subdomain") or s.get("host")))
    subdomain_count = len(unique_subdomains)
    if subdomain_count == 0:
        subdomains_details = "None discovered"
    else:
        sample_subdomains = unique_subdomains[:10]
        subdomains_details = ", ".join(sample_subdomains)
        if subdomain_count > 10:
            subdomains_details += f" ... (and {subdomain_count - 10} more)"

    # Process Ports
    seen_ports = set()
    unique_ports = []
    for p in ports_list:
        port_num = p.get("port")
        proto = p.get("protocol") or "tcp"
        if port_num:
            port_key = f"{port_num}/{proto}"
            if port_key not in seen_ports:
                seen_ports.add(port_key)
                unique_ports.append(f"{target}:{port_key}")
    port_count = len(unique_ports)
    ports_details = ", ".join(unique_ports) if unique_ports else "None discovered"

    # Process HTTP Services
    seen_urls = set()
    unique_services = []
    for s in http_probes:
        url = s.get("url")
        status_code = s.get("status_code") or 200
        title = s.get("title") or "N/A"
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique_services.append(f"{url} ({status_code}) - {title}")
    service_count = len(unique_services)
    services_details = "<br/>".join(unique_services) if unique_services else "None discovered"

    # 3. Compliance Mapping
    owasp_mappings = sorted(list(set(
        f.get("owasp_category") for f in enriched_findings if f.get("owasp_category") and f.get("owasp_category") != "Unknown"
    )))
    owasp_mapping_str = ", ".join(owasp_mappings) if owasp_mappings else "N/A"

    # 4. Tool Status
    tool_status_rows = []
    default_tools = ["subfinder", "amass", "naabu", "nmap", "httpx_probe", "whatweb", "nuclei", "nikto", "dalfox", "zap"]
    if scan_doc:
        tr = scan_doc.get("tool_results", {})
        for t in default_tools:
            t_data = tr.get(t)
            if t_data:
                t_status = t_data.get("status")
                status_str = "Success" if t_status == "completed" else ("Needs attention" if t_status == "failed" else "Unknown")
                error_cnt = 1 if t_status == "failed" else 0
                available_str = "Yes"
            else:
                status_str = "Skipped"
                error_cnt = 0
                available_str = "No"
            tool_status_rows.append({
                "tool": t,
                "available": available_str,
                "status": status_str,
                "errors": error_cnt
            })
    else:
        # Fallback if scan_doc doesn't exist
        for t in default_tools:
            tool_status_rows.append({
                "tool": t,
                "available": "Unknown",
                "status": "Needs attention",
                "errors": 0
            })

    # 5. Metadata JSON dumps for page 6
    generated_at_str = report_data.get("generated_at") or datetime.utcnow().isoformat()
    ai_analysis_meta = {
        "version": "1.0",
        "generated_at": generated_at_str,
        "data": {
            "provider": settings.ai_provider,
            "model": settings.openai_model if settings.ai_provider == "openai" else (settings.anthropic_model if settings.ai_provider == "claude" else settings.ollama_model),
            "status": "completed"
        }
    }
    asset_inventory_meta = {
        "subdomains": unique_subdomains[:3],
        "ports": [{"host": target, "port": p.split(":")[-1]} for p in unique_ports[:3]],
        "host": target
    }
    methodology_meta = {
        "stages": ["Recon", "Network", "Web", "Correlation", "Risk Scoring", "Reporting"]
    }
    risk_summary_meta = {
        "critical": critical_cnt,
        "high": high_cnt,
        "medium": medium_cnt,
        "low": low_cnt,
        "info": info_cnt
    }
    validation_meta = {
        "invalid_findings": 0,
        "validation_errors": [],
        "validated_findings": total_findings
    }

    # Prepare Template Context
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("report.html")

    context = {
        "target": target,
        "status": status,
        "scan_type": scan_type,
        "overall_risk": overall_rating,
        "risk_score": overall_score,
        "total_findings": total_findings,
        "generated_at": generated_at_str,
        "report_version": "2.0",
        
        "critical_count": critical_cnt,
        "high_count": high_cnt,
        "medium_count": medium_cnt,
        "low_count": low_cnt,
        "info_count": info_cnt,
        
        "subdomain_count": subdomain_count,
        "subdomains_details": subdomains_details,
        "port_count": port_count,
        "ports_details": ports_details,
        "service_count": service_count,
        "services_details": services_details,
        
        "owasp_mapping": owasp_mapping_str,
        "findings": enriched_findings,
        
        "tool_status": tool_status_rows,
        
        "meta_ai_analysis": json.dumps(ai_analysis_meta, indent=2),
        "meta_asset_inventory": json.dumps(asset_inventory_meta, indent=2),
        "meta_methodology": json.dumps(methodology_meta, indent=2),
        "meta_risk_summary": json.dumps(risk_summary_meta, indent=2),
        "meta_validation": json.dumps(validation_meta, indent=2),
    }

    html_content = template.render(**context)

    # Convert to PDF / Save outputs
    os.makedirs(settings.reports_dir, exist_ok=True)
    pdf_path = os.path.join(settings.reports_dir, f"argolock_report_{scan_id}.pdf")
    html_path = os.path.join(settings.reports_dir, f"argolock_report_{scan_id}.html")

    # Always write HTML report for rendering/reviewing
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info(f"HTML report written to {html_path}")

    if weasyprint:
        try:
            pdf = weasyprint.HTML(string=html_content).write_pdf()
            with open(pdf_path, "wb") as f:
                f.write(pdf)
            logger.info(f"PDF report written to {pdf_path}")
            return pdf_path
        except Exception as e:
            logger.error(f"WeasyPrint failed to compile PDF: {e}")
            
    # If PDF compilation fails or WeasyPrint is unavailable, return HTML path as fallback
    return html_path
