import os
import time
import subprocess
import re
import threading
import uuid
import json
import logging
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify
from backend.core.config import SCAN_PROFILES, DEFAULT_NMAP_CANDIDATES, REPORTS_DIR
from backend.core.tasks import SCAN_TASKS

nmap_bp = Blueprint('nmap', __name__)
logger = logging.getLogger(__name__)


def sanitize_target(raw_target):
    """
    Extracts a bare hostname or IP from user input.
    Nmap cannot accept full URLs like 'http://example.com/path' —
    it needs just the hostname or IP address.
    
    Examples:
        'http://testasp.vulnweb.com/'  -> 'testasp.vulnweb.com'
        'https://example.com:8443/app' -> 'example.com'
        '192.168.1.1'                  -> '192.168.1.1'
        'scanme.nmap.org'              -> 'scanme.nmap.org'
        '192.168.1.0/24'              -> '192.168.1.0/24'  (CIDR preserved)
    """
    target = raw_target.strip()
    if not target:
        return target

    # If it looks like a URL (has a scheme), parse it properly
    if re.match(r'^https?://', target, re.IGNORECASE):
        parsed = urlparse(target)
        # hostname strips port; use it over netloc
        target = parsed.hostname or parsed.netloc.split(':')[0]
    else:
        # No scheme — but could still have a port like 'example.com:8080'
        # Don't strip port from CIDR notation (e.g. 192.168.1.0/24)
        if '/' not in target and ':' in target:
            target = target.split(':')[0]
        # Strip any trailing path-like segments for bare hostnames
        elif '/' in target and not re.match(r'^\d+\.\d+\.\d+\.\d+/', target):
            target = target.split('/')[0]

    return target


def run_nmap_scan(target, scan_type, task_id=None, owner_id=None):
    """Executes Nmap via subprocess with XML output and real-time progress."""
    start_time = time.time()
    nmap_exe = "nmap"
    for candidate in DEFAULT_NMAP_CANDIDATES:
        if candidate and os.path.exists(candidate):
            nmap_exe = os.path.normpath(candidate)
            break
    
    # Sanitize target: strip URL scheme, path, port — nmap needs bare host/IP
    original_target = target
    target = sanitize_target(target)
    if original_target != target:
        logger.info(f"[NMAP] Sanitized target: '{original_target}' -> '{target}'")

    if not target:
        error_msg = "Target is empty after sanitization."
        logger.error(f"[NMAP] {error_msg}")
        if task_id:
            SCAN_TASKS[task_id].update({"status": "failed", "error": error_msg})
        return None

    report_id = uuid.uuid4().hex
    xml_file = REPORTS_DIR / f"nmap_{report_id}.xml"
    args = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["Regular Scan"])
    cmd_args = [nmap_exe] + args.split() + ["-vv", "--stats-every", "1s", "-oX", str(xml_file), target]
    
    logger.info(f"[NMAP] Executing: {' '.join(cmd_args)}")

    try:
        process = subprocess.Popen(
            cmd_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", shell=False
        )
        
        nmap_output_lines = []
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None: break
            if line:
                nmap_output_lines.append(line.rstrip())
                if task_id:
                    # Optimized progress regex for Nmap
                    match = re.search(r"(\d+\.\d+)%", line)
                    if match:
                        SCAN_TASKS[task_id]["progress"] = float(match.group(1))
        
        exit_code = process.wait()
        logger.info(f"[NMAP] Process exited with code: {exit_code}")
        
        # Parse XML Results
        services = []
        open_ports = 0
        filtered_ports = 0
        hosts_up = 0

        if xml_file.exists() and xml_file.stat().st_size > 0:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall('host'):
                # Only count hosts that are actually up
                status_elem = host.find('status')
                if status_elem is not None and status_elem.get('state') != 'up':
                    continue
                hosts_up += 1
                addr_elem = host.find('address')
                addr = addr_elem.get('addr') if addr_elem is not None else target
                for port_elem in host.findall('.//port'):
                    port_id = port_elem.get('portid')
                    proto = port_elem.get('protocol')
                    state_elem = port_elem.find('state')
                    state = state_elem.get('state') if state_elem is not None else "unknown"
                    
                    if state == "open": open_ports += 1
                    elif state == "filtered": filtered_ports += 1
                    
                    service_elem = port_elem.find('service')
                    service_name = service_elem.get('name') if service_elem is not None else "unknown"
                    product = service_elem.get('product') if service_elem is not None else ""
                    version = service_elem.get('version') if service_elem is not None else ""
                    
                    services.append({
                        "host": addr, "protocol": proto, "port": port_id,
                        "state": state, "service": service_name,
                        "version": version, "product": product,
                    })
            
            # Clean up XML file
            xml_file.unlink()
        else:
            # No XML output — nmap likely failed to resolve or scan the target
            logger.warning(f"[NMAP] No XML output produced for target '{target}'")
            # Check nmap output for specific error messages
            error_lines = [l for l in nmap_output_lines if 'unable to' in l.lower() or 'warning' in l.lower() or 'error' in l.lower()]
            if error_lines:
                logger.warning(f"[NMAP] Nmap errors: {'; '.join(error_lines)}")

        result = {
            "target": target, "scan_type": scan_type, "hosts": hosts_up,
            "open_ports": open_ports, "filtered_ports": filtered_ports,
            "duration": f"{time.time() - start_time:.2f}s", "services": services,
        }
        
        # Persist Result as JSON Report (matches ZAP format)
        report_data = {"tool": "NETWORK", "owner_id": owner_id, "data": result}
        with open(REPORTS_DIR / f"{report_id}.json", "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        if task_id:
            SCAN_TASKS[task_id].update({
                "status": "completed", 
                "progress": 100, 
                "result": {"report_id": report_id, **result}
            })
        return result
    except Exception as e:
        logger.exception(f"[NMAP] Scan failed for target '{target}': {e}")
        if task_id:
            SCAN_TASKS[task_id].update({"status": "failed", "error": str(e)})
        if xml_file.exists(): xml_file.unlink()
        raise e


@nmap_bp.route("/api/network/scan", methods=["POST"])
def api_nmap_scan():
    try:
        data = request.json
        raw_target = data.get("target", "").strip()
        scan_type = data.get("scan_type", "Quick Scan")

        if not raw_target:
            return jsonify({"success": False, "error": "Target is required."}), 400

        # Sanitize before starting the thread so we can validate early
        clean_target = sanitize_target(raw_target)
        if not clean_target:
            return jsonify({"success": False, "error": f"Could not extract a valid hostname from: {raw_target}"}), 400

        from flask_login import current_user
        owner_id = current_user.id if getattr(current_user, 'is_authenticated', False) else None

        task_id = uuid.uuid4().hex
        SCAN_TASKS[task_id] = {"status": "running", "progress": 0, "result": None, "error": None}
        thread = threading.Thread(target=run_nmap_scan, args=(clean_target, scan_type, task_id, owner_id))
        thread.daemon = True
        thread.start()
        return jsonify({"success": True, "task_id": task_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
