import json
import time
import re
import urllib.parse
from flask import Blueprint, request, render_template, jsonify
from backend.core.config import REPORTS_DIR
from backend.core.helpers import get_report_data

analytics_bp = Blueprint('analytics', __name__)

def perform_analytics(nmap, zap):
    waf_detected = nmap.get("filtered_ports", 0) > 0
    services_map = {svc["port"]: f"{svc['service']} ({svc['version'] or svc['product'] or 'Unknown'})".replace('"', "'") for svc in nmap.get("services", []) if svc["state"] == "open"}
    findings, target_label = [], nmap.get('target', 'Target').replace('"', "'")
    mermaid_lines = ["graph LR", f"    Internet((Internet)) --> Target[\"{target_label}\"]"]
    
    def sanitize_id(text): return re.sub(r'[^a-zA-Z0-9_]', '_', str(text))

    for alert in zap.get("alerts", []):
        risk, name = alert.get("risk", "Info"), alert.get("name", "Unknown").replace('"', "'")
        score = {"High": 8.5, "Medium": 5.5, "Low": 2.5, "Info": 1.0}.get(risk, 1.0)
        if any(kw in name.lower() for kw in ["sql injection", "remote code execution", "rce"]) and not waf_detected:
            score, risk = 9.9, "Critical"
        elif waf_detected: score = max(1.0, score - 2.0)
            
        port_found = next((p for p in services_map.keys() if f":{p}" in alert.get("instances", "")), None)
        findings.append({"name": name, "risk": risk, "score": score, "port": port_found, "service": services_map.get(port_found, "Web Service") if port_found else "Web Service", "evidence": alert.get("evidence"), "attack": alert.get("attack"), "url": alert.get("url"), "method": alert.get("method"), "parameter": alert.get("parameter")})
        
        node_id = sanitize_id(f"vuln_{name[:30]}_{port_found or 'web'}")
        if port_found:
            p_id, s_id = f"Port_{port_found}", sanitize_id(f"Svc_{port_found}")
            mermaid_lines.extend([f"    Target --> {p_id}[\"Port {port_found}\"]", f"    {p_id} --> {s_id}[\"{services_map[port_found]}\"]", f"    {s_id} --> {node_id}[\"{name} (Score: {score})\"]"])
        else:
            mermaid_lines.extend(["    Target --> Web[\"Web Services\"]", f"    Web --> {node_id}[\"{name} (Score: {score})\"]"])

    findings.sort(key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(x["risk"], 5))
    return {"waf_detected": waf_detected, "findings": findings, "mermaid_graph": "graph LR\n" + "\n".join(list(set(mermaid_lines) - {"graph LR"}))}

@analytics_bp.route("/analytics")
def analytics_page():
    all_reports = []
    stats = {
        "total_scans": 0, "high_risks": 0, "med_risks": 0, "low_risks": 0, 
        "top_findings": {}, "service_distribution": {},
        "trend_labels": [], "trend_data": [], "recent_scans": []
    }

    # Temporary storage for trend data (scans per day)
    import datetime
    today = datetime.date.today()
    trend_counts = { (today - datetime.timedelta(days=i)).strftime("%Y-%m-%d"): 0 for i in range(6, -1, -1) }

    for f in REPORTS_DIR.glob("*.json"):
        try:
            with open(f, "r", encoding="utf-8") as file:
                data = json.load(file)
                name = f.stem
                mtime = f.stat().st_mtime
                mdate = datetime.date.fromtimestamp(mtime).strftime("%Y-%m-%d")
                
                # Trend collection
                if mdate in trend_counts:
                    trend_counts[mdate] += 1
                
                tool = data.get("tool")
                # Backward compat: normalize old tool names
                if tool == "NMAP": tool = "NETWORK"
                elif tool == "ZAP": tool = "WEBAPP"
                
                report_data = data.get("data", {})
                item = {
                    "id": name, 
                    "tool": tool, 
                    "target": report_data.get("target", "Unknown"), 
                    "time": time.ctime(mtime),
                    "high": report_data.get("high", 0),
                    "medium": report_data.get("medium", 0),
                    "low": report_data.get("low", 0)
                }
                all_reports.append(item)
                
                # Global Stats Accumulation
                stats["total_scans"] += 1
                
                if tool == "NETWORK":
                    for svc in report_data.get("services", []):
                        s_name = svc.get("service", "unknown")
                        stats["service_distribution"][s_name] = stats["service_distribution"].get(s_name, 0) + 1
                
                elif tool == "WEBAPP":
                    stats["high_risks"] += report_data.get("high", 0)
                    stats["med_risks"] += report_data.get("medium", 0)
                    stats["low_risks"] += report_data.get("low", 0)
                    for alert in report_data.get("alerts", []):
                        a_name = alert.get("name", "Unknown")
                        stats["top_findings"][a_name] = stats["top_findings"].get(a_name, 0) + 1
        except: continue
    
    # Sort findings for charts
    stats["top_findings"] = dict(sorted(stats["top_findings"].items(), key=lambda x: x[1], reverse=True)[:5])
    stats["service_distribution"] = dict(sorted(stats["service_distribution"].items(), key=lambda x: x[1], reverse=True)[:5])
    
    # Finalize trend data
    stats["trend_labels"] = list(trend_counts.keys())
    stats["trend_data"] = list(trend_counts.values())
    
    # Populate recent scans (last 5)
    all_reports.sort(key=lambda x: x["time"], reverse=True)
    stats["recent_scans"] = all_reports[:5]


    nmap_id, zap_id = request.args.get("nmap_id"), request.args.get("zap_id")
    analysis, error = None, None
    if nmap_id and zap_id:
        nmap_data, zap_data = get_report_data(nmap_id), get_report_data(zap_id)
        if nmap_data and zap_data:
            def norm(t): return (urllib.parse.urlparse('http://'+t if not t.startswith(('http://','https://')) else t).hostname or t).lower().replace('www.','')
            if norm(nmap_data["data"].get("target","")) != norm(zap_data["data"].get("target","")):
                error = "Target Mismatch: Select reports for the same domain."
            else: analysis = perform_analytics(nmap_data["data"], zap_data["data"])
            
    return render_template("vapt_views/analytics.html", reports=all_reports, stats=stats, analysis=analysis, nmap_id=nmap_id, zap_id=zap_id, target_error=error)
