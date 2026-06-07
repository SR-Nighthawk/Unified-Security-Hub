import os
import uuid
import tempfile
import socket
import subprocess
import threading
import json
import time
import logging
import re
from flask import Blueprint, request, jsonify
from bs4 import BeautifulSoup
from backend.core.config import DEFAULT_ZAP_PATH, REPORTS_DIR, ZAP_API_URL, ZAP_API_KEY
from backend.core.tasks import SCAN_TASKS, REPORT_INDEX
import requests as http_requests

zap_bp = Blueprint('zap', __name__)
logger = logging.getLogger(__name__)

def parse_zap_report(report_html):
    soup = BeautifulSoup(report_html, "html.parser")
    site_name = "Unknown"
    generated_on = "Unknown"
    site_header = soup.find("h2")
    if site_header:
        site_name = site_header.get_text(strip=True).replace("Sites:", "").strip() or "Unknown"
    h3_headers = soup.find_all("h3")
    if h3_headers:
        generated_on = h3_headers[0].get_text(strip=True).replace("Generated on", "").strip() or "Unknown"

    summary_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    summary_table = soup.find("table", class_="summary")
    if summary_table:
        for row in summary_table.find_all("tr")[1:]:
            cols = row.find_all("td")
            if len(cols) >= 2:
                level = cols[0].get_text(strip=True)
                try: summary_counts[level] = int(cols[1].get_text(strip=True))
                except: pass

    alerts = []
    for results_table in soup.find_all("table", class_="results"):
        detail = {"name": "Unknown", "risk": "Info", "confidence": "Unknown", "solution": "", "description": "", "instances": "", "reference": "", "url": "", "method": "GET", "parameter": "", "attack": "", "evidence": ""}
        header_row = results_table.find("tr")
        if header_row:
            headers = header_row.find_all("th")
            if len(headers) >= 2:
                detail["risk"] = headers[0].get_text(strip=True) or "Info"
                detail["name"] = headers[1].get_text(strip=True) or "Unknown"
        for row in results_table.find_all("tr")[1:]:
            cols = row.find_all("td")
            if len(cols) == 2:
                key, value = cols[0].get_text(strip=True), cols[1].get_text(" ", strip=True)
                if key == "Confidence": detail["confidence"] = value
                elif key == "Solution": detail["solution"] = value
                elif key == "Description": detail["description"] = value
                elif key == "Instances": detail["instances"] = value
                elif key == "Reference": detail["reference"] = value
                elif key == "URL":
                    link = cols[1].find("a")
                    detail["url"] = link["href"] if link and link.has_attr("href") else value
                elif key in ["Method", "Parameter", "Attack", "Evidence"]:
                    detail[key.lower()] = value
        alerts.append(detail)
    
    return {
        "site": site_name, "generated_on": generated_on,
        "high": summary_counts.get("High", 0), "medium": summary_counts.get("Medium", 0),
        "low": summary_counts.get("Low", 0), "info": summary_counts.get("Info", 0),
        "total": sum(summary_counts.values()) or len(alerts), "alerts": alerts,
    }

def run_zap_scan(exe_path, target_url, task_id=None, auth_login_url=None, auth_username=None, auth_password=None, owner_id=None, scan_type="active"):
    try:
        if not os.path.exists(exe_path): raise FileNotFoundError(f"ZAP.exe not found at {exe_path}")
        report_id = uuid.uuid4().hex
        report_file = REPORTS_DIR / f"zap_report_{report_id}.html"

        zap_home = tempfile.mkdtemp(prefix="zap_home_")
        zap_dir = os.path.dirname(exe_path)
        
        # Handle Authentication Block if Provided
        auth_yaml = ""
        user_param = ""
        if auth_login_url and auth_username and auth_password:
            auth_yaml = f"""
      authentication:
        method: "form"
        parameters:
          loginPageUrl: "{auth_login_url}"
          loginRequestUrl: "{auth_login_url}"
          loginRequestBody: "username={{%username%}}&password={{%password%}}"
        verification:
          method: "response"
          loggedOutRegex: "login|sign in"
      users:
        - name: "ScanUser"
          credentials:
            username: "{auth_username}"
            password: "{auth_password}"
"""
            user_param = '\n      user: "ScanUser"'

        # Provide posix-style paths to avoid YAML interpretation of backslashes (\U) as malformed unicode escapes
        import pathlib
        report_dir_posix = pathlib.Path(report_file.parent).resolve().as_posix()

        # Inject Automation Framework YAML configuration
        # Includes advanced Ajax spider and insane active scan strength
        jobs_yaml_components = [f"""env:
  contexts:
    - name: "TargetContext"
      urls: ["{target_url}"]{auth_yaml}
jobs:
  - type: spider
    parameters:
      context: "TargetContext"{user_param}
  - type: spiderAjax
    parameters:
      context: "TargetContext"{user_param}"""]

        if scan_type == "active":
            jobs_yaml_components.append(f"""  - type: activeScan
    parameters:
      context: "TargetContext"{user_param}
      policy: "Default Policy"
    policyDefinition:
      defaultStrength: "insane"
      defaultThreshold: "low" """)

        jobs_yaml_components.append(f"""  - type: report
    parameters:
      template: "traditional-html"  # Maps exactly to the quickout legacy format we parse
      reportDir: "{report_dir_posix}"
      reportFile: "{report_file.name}" """)

        auth_config = "\n".join(jobs_yaml_components)
        config_path = os.path.join(zap_home, "config.yaml")
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(auth_config)
        
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_sock.bind(("", 0))
        zap_port = str(temp_sock.getsockname()[1])
        temp_sock.close()
        
        cmd_args = [
            os.path.normpath(exe_path), "-cmd", "-dir", zap_home, "-port", zap_port, 
            "-autorun", config_path, 
            "-config", "api.disablekey=true", "-config", "api.addrs.addr.name=127.0.0.1", "-config", "api.addrs.addr.ispregex=false"
        ]
        
        process = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=zap_dir, text=True, encoding="utf-8", errors="replace", shell=False)
        
        output_lines = []
        if process.stdout is not None:
            import re
            while True:
                line = process.stdout.readline()
                if line == "" and process.poll() is not None: break
                if line and task_id:
                    if "progress" in line.lower() and "%" in line:
                        try:
                            percent = re.search(r"(\d+)", line)
                            if percent:
                                val = int(percent.group(1))
                                if "spider" in line.lower():
                                    SCAN_TASKS[task_id]["progress"] = val * 0.3 if scan_type == "active" else val
                                else:
                                    SCAN_TASKS[task_id]["progress"] = 30 + (val * 0.7) if scan_type == "active" else 100
                        except: pass
                    output_lines.append(line.strip())
        process.wait()
        
        if task_id:
            if not report_file.exists():
                SCAN_TASKS[task_id].update({"status": "failed", "error": "ZAP report not created."})
                return
            with open(report_file, "r", encoding="utf-8") as f:
                report_data = parse_zap_report(f.read())
            
            # Consistent result structure
            full_result = {"report_id": report_id, "target": target_url, "tool": "WEBAPP", **report_data}
            
            # Persist as JSON for history/report views
            json_report = {"tool": "WEBAPP", "owner_id": owner_id, "data": full_result}
            with open(REPORTS_DIR / f"{report_id}.json", "w", encoding="utf-8") as f:
                json.dump(json_report, f, indent=2)

            SCAN_TASKS[task_id].update({"status": "completed", "progress": 100, "result": full_result})
        
        return {"report_id": report_id, **report_data}
    except Exception as e:
        print(f"[ZAP] Scan failed: {e}")
        if task_id:
            SCAN_TASKS[task_id].update({"status": "failed", "error": str(e), "progress": 0})
        return None

def run_zap_api_scan(target_url, task_id=None, scan_type="active", owner_id=None):
    """Run ZAP scan via REST API (Docker mode — connects to ZAP container)."""
    try:
        zap_base = ZAP_API_URL.rstrip('/')
        report_id = uuid.uuid4().hex

        # 1. Open URL in ZAP
        logger.info(f"[ZAP-API] Opening target: {target_url}")
        http_requests.get(f"{zap_base}/JSON/core/action/accessUrl/",
                          params={"url": target_url, "followRedirects": "true"},
                          timeout=30)

        # 2. Spider
        logger.info(f"[ZAP-API] Starting spider...")
        r = http_requests.get(f"{zap_base}/JSON/spider/action/scan/",
                              params={"url": target_url, "maxChildren": "10"},
                              timeout=10)
        spider_id = r.json().get("scan", "0")
        while True:
            status = http_requests.get(f"{zap_base}/JSON/spider/view/status/",
                                       params={"scanId": spider_id}, timeout=10).json()
            progress = int(status.get("status", "100"))
            if task_id:
                SCAN_TASKS[task_id]["progress"] = progress * 0.3 if scan_type == "active" else progress
            if progress >= 100:
                break
            time.sleep(2)

        # 3. Active Scan (if requested)
        if scan_type == "active":
            logger.info(f"[ZAP-API] Starting active scan...")
            r = http_requests.get(f"{zap_base}/JSON/ascan/action/scan/",
                                  params={"url": target_url, "recurse": "true"},
                                  timeout=10)
            scan_id = r.json().get("scan", "0")
            while True:
                status = http_requests.get(f"{zap_base}/JSON/ascan/view/status/",
                                           params={"scanId": scan_id}, timeout=10).json()
                progress = int(status.get("status", "100"))
                if task_id:
                    SCAN_TASKS[task_id]["progress"] = 30 + (progress * 0.7)
                if progress >= 100:
                    break
                time.sleep(3)

        # 4. Fetch Alerts
        alerts_resp = http_requests.get(f"{zap_base}/JSON/alert/view/alerts/",
                                        params={"baseurl": target_url, "start": "0", "count": "500"},
                                        timeout=30).json()
        raw_alerts = alerts_resp.get("alerts", [])

        # Parse into our standard format
        summary_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        alerts = []
        for a in raw_alerts:
            risk = a.get("risk", "Info")
            summary_counts[risk] = summary_counts.get(risk, 0) + 1
            alerts.append({
                "name": a.get("name", "Unknown"),
                "risk": risk,
                "confidence": a.get("confidence", "Unknown"),
                "description": a.get("description", ""),
                "solution": a.get("solution", ""),
                "url": a.get("url", ""),
                "method": a.get("method", "GET"),
                "parameter": a.get("param", ""),
                "attack": a.get("attack", ""),
                "evidence": a.get("evidence", ""),
                "reference": a.get("reference", ""),
                "instances": "",
            })

        report_data = {
            "site": target_url, "generated_on": time.strftime("%Y-%m-%d %H:%M:%S"),
            "high": summary_counts.get("High", 0), "medium": summary_counts.get("Medium", 0),
            "low": summary_counts.get("Low", 0), "info": summary_counts.get("Info", 0),
            "total": sum(summary_counts.values()), "alerts": alerts,
        }

        full_result = {"report_id": report_id, "target": target_url, "tool": "WEBAPP", **report_data}
        json_report = {"tool": "WEBAPP", "owner_id": owner_id, "data": full_result}
        with open(REPORTS_DIR / f"{report_id}.json", "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2)

        if task_id:
            SCAN_TASKS[task_id].update({"status": "completed", "progress": 100, "result": full_result})
        return full_result

    except Exception as e:
        logger.exception(f"[ZAP-API] Scan failed: {e}")
        if task_id:
            SCAN_TASKS[task_id].update({"status": "failed", "error": str(e), "progress": 0})
        return None


@zap_bp.route("/api/web/scan", methods=["POST"])
def api_zap_scan():
    try:
        data = request.json
        target_url = data.get("target")
        scan_type = data.get("scan_type", "active")

        from flask_login import current_user
        owner_id = current_user.id if getattr(current_user, 'is_authenticated', False) else None

        task_id = uuid.uuid4().hex
        SCAN_TASKS[task_id] = {"status": "running", "progress": 0, "result": None, "error": None}

        # Choose ZAP mode: API (Docker) vs CLI (local)
        if ZAP_API_URL:
            logger.info(f"[ZAP] Using API mode: {ZAP_API_URL}")
            thread = threading.Thread(
                target=run_zap_api_scan,
                args=(target_url, task_id, scan_type, owner_id)
            )
        else:
            exe_path = data.get("exe_path", DEFAULT_ZAP_PATH)
            auth_login_url = data.get("auth_login_url", None)
            auth_username = data.get("auth_username", None)
            auth_password = data.get("auth_password", None)
            logger.info(f"[ZAP] Using CLI mode: {exe_path}")
            thread = threading.Thread(
                target=run_zap_scan,
                args=(exe_path, target_url, task_id, auth_login_url, auth_username, auth_password, owner_id, scan_type)
            )

        thread.daemon = True
        thread.start()
        return jsonify({"success": True, "task_id": task_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
