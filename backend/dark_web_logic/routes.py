import os, re, threading, requests, time, hashlib, asyncio, json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, send_file, request, jsonify
from flask_socketio import SocketIO
from google import genai
from urllib.parse import urljoin
from playwright.async_api import async_playwright
from dotenv import load_dotenv
from bs4 import BeautifulSoup

# PDF Core Libraries
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Load .env
load_dotenv()

from backend.models import APTGroup, GroupLink, LinkStatusHistory, DiscoveryLog
from backend.apt_worker import start_scheduler
from backend.core.config import TOR_PROXIES as _TOR_PROXIES, TOR_SOCKS_URL

from flask import Blueprint, current_app
from backend.extensions import socketio, db
from flask_login import login_required

dark_web_bp = Blueprint('dark_web_bp', __name__)

# --- CONFIG ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    print("WARNING: GEMINI_API_KEY NOT FOUND IN .ENV — AI features will be disabled.")

# Lazy-initialise the Gemini client so a missing key doesn't crash startup.
_gemini_client = None

def get_gemini_client():
    """Return a cached Gemini client, or None if no API key is configured."""
    global _gemini_client
    if _gemini_client is None:
        key = os.getenv("GEMINI_API_KEY")
        if not key:
            return None
        _gemini_client = genai.Client(api_key=key)
    return _gemini_client

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")
TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TG_CHAT = os.getenv("TELEGRAM_CHAT_ID")

# Tor Configuration — sourced from centralized config (Docker-aware)
TOR_PROXIES = _TOR_PROXIES
TOR_PROXIES_LH = _TOR_PROXIES
TOR_SOCKS = TOR_SOCKS_URL

# Vault and static directories — use absolute paths from project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
VAULT_DIR = str(_PROJECT_ROOT / "data")
VAULT_FILE = os.path.join(VAULT_DIR, "intel_vault.json")
STATIC_DIR = str(_PROJECT_ROOT / "static")
os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# Helper to write to disk immediately so PDF can find it
def write_to_vault(entry):
    data = []
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, 'r', encoding='utf-8') as f:
            try: 
                data = json.load(f)
                if not isinstance(data, list): data = []
            except Exception as e:
                print(f"Vault Read Error: {e}")
                data = []
    
    # Check for duplicates by URL
    if not any(item['url'] == entry['url'] for item in data):
        data.append(entry)
        with open(VAULT_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        return True
    return False

from concurrent.futures import ThreadPoolExecutor

class IntelEngine:
    def __init__(self, keyword, socket, max_depth=2):
        self.keyword = keyword.lower()
        self.socket = socket
        self.visited = set()
        self.session_found = set()
        self.found_count = 0
        self.max_depth = max_depth
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.queue = []

    def status(self, msg, status_type="info"):
        self.socket.emit('status_update', {'msg': msg, 'type': status_type})

    async def get_screenshot(self, url, entry_id):
        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(proxy={"server": TOR_SOCKS})
                page = await browser.new_page()
                await page.set_viewport_size({"width": 1280, "height": 720})
                await page.goto(url, timeout=60000, wait_until="commit")
                path = f"static/proof_{entry_id}.png"
                await page.screenshot(path=path)
                await browser.close()
                return path
            except: return None

    def nvidia_analyze(self, keyword):
        if not NVIDIA_API_KEY: return None
        try:
            url = "https://integrate.api.nvidia.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {NVIDIA_API_KEY}", "Content-Type": "application/json"}
            payload = {
                "model": "mistralai/mistral-small-4-119b-2603",
                "messages": [{"role": "user", "content": f"Analyze dark web content for '{keyword}'. Return format: THREAT: [X]\nENTITIES: [E]\nVICTIMS: [V]\nSUMMARY: [S]"}],
                "max_tokens": 1024, "temperature": 0.1
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=(5, 30))
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content']
        except: pass
        return None

    def send_telegram_alert(self, entry):
        if not TG_TOKEN or not TG_CHAT: return
        try:
            msg = (f"🚨 DARK WEB ALERT 🚨\n\n"
                   f"ID: {entry['id']}\n"
                   f"URL: {entry['url']}\n"
                   f"RISK: {entry['risk_score']}% [{entry['threat']}]\n\n"
                   f"VICTIMS: {entry['victims']}\n"
                   f"SUMMARY: {entry['intel'][:200]}...")
            url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
            requests.post(url, json={"chat_id": TG_CHAT, "text": msg}, timeout=10)
        except: pass

    def process_url(self, url, depth):
        if self.stop_event.is_set(): return
        with self.lock:
            if url in self.visited or self.found_count >= 50: return
            self.visited.add(url)
        
        self.status(f"Scanning (Depth {depth}): {url[:50]}...")
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:120.0) Gecko/20100101 Firefox/120.0'}
            prox = TOR_PROXIES_LH if ".onion" in url else None
            r = requests.get(url, proxies=prox, headers=headers, timeout=40, verify=False)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            # Discovery: Smart Prioritized Extraction
            if depth < self.max_depth or (depth < 4 and "darkwebdaily" in url):
                links = soup.find_all('a', href=True)
                added_count = 0
                for a in links:
                    link = a['href'].strip()
                    if not link.startswith('http'): link = urljoin(url, link)
                    
                    if ".onion" in link:
                        text = a.text.lower()
                        priority = any(k in text or k in link.lower() for k in ["market", "forum", "shop", "vendor", "directory", "index", "link"])
                        with self.lock:
                            if self.stop_event.is_set(): return
                            if link not in self.visited:
                                added_count += 1
                                if priority: self.queue.insert(0, (link, depth + 1))
                                else: self.queue.append((link, depth + 1))
                
                # Anti-Blocking for Search Engines
                if "juhanurmi" in url or "xmh57" in url or "haystak" in url:
                    import random
                    time.sleep(random.uniform(1.5, 3.5))
                
                # Fallback: Raw Regex Discovery
                raw_onions = re.findall(r"([a-z2-7]{16}|[a-z2-7]{56})\.onion", r.text.lower())
                for o in list(set(raw_onions)):
                    link = f"http://{o}.onion"
                    with self.lock:
                        if link not in self.visited:
                            added_count += 1
                            self.queue.append((link, depth + 1))
                
                if added_count > 0:
                    self.status(f"Discovered {added_count} new links at Depth {depth}", "info")

            # Keyword Intelligence Verification (Fuzzy Matching)
            # Support partial matches or variations (e.g., 'petadot' matches 'peta-dot' or 'petadot.com')
            fuzzy_keyword = self.keyword.replace(" ", ".*")
            is_match = re.search(fuzzy_keyword, r.text.lower())
            
            is_search_engine = any(s in url for s in ["juhanurmi", "xmh57", "haystak"])
            
            if ".onion" in url and is_match and not is_search_engine:
                entry_id = str(hashlib.md5(url.encode()).hexdigest()[:6])
                self.status(f"INTEL VERIFIED: {entry_id}", "success")
                
                threat, entities, victims, summary, risk_score = "MEDIUM", "None", "Unknown", "Analysis in progress...", 50
                models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-flash-latest", "gemini-pro-latest"]
                ai_success, last_error = False, ""

                for model_id in models_to_try:
                    try:
                        prompt = (f"Analyze dark web content for '{self.keyword}' at {url}. "
                                  f"Return ONLY this format:\n"
                                  f"RISK: [0-100]\n"
                                  f"THREAT: LOW/MEDIUM/HIGH/CRITICAL\n"
                                  f"ENTITIES: [Emails/Crypto/Users]\n"
                                  f"VICTIMS: [Who is targeted?]\n"
                                  f"SUMMARY: [Brief technical details]")
                        
                        _gc = get_gemini_client()
                        if not _gc:
                            last_error = "GEMINI_API_KEY not configured"
                            break
                        ai_resp = _gc.models.generate_content(model=model_id, contents=prompt)
                        res_text = ai_resp.text
                        for line in res_text.split("\n"):
                            if line.startswith("RISK:"): risk_score = int(''.join(filter(str.isdigit, line)))
                            elif line.startswith("THREAT:"): threat = line.replace("THREAT:", "").strip()
                            elif line.startswith("ENTITIES:"): entities = line.replace("ENTITIES:", "").strip()
                            elif line.startswith("VICTIMS:"): victims = line.replace("VICTIMS:", "").strip()
                            elif line.startswith("SUMMARY:"): summary = line.replace("SUMMARY:", "").strip()
                        ai_success = True
                        break
                    except Exception as e: last_error = str(e); continue

                if not ai_success and NVIDIA_API_KEY:
                    mistral_resp = self.nvidia_analyze(self.keyword)
                    if mistral_resp:
                        for line in mistral_resp.split("\n"):
                            if line.startswith("RISK:"): risk_score = int(''.join(filter(str.isdigit, line)))
                            elif line.startswith("THREAT:"): threat = line.replace("THREAT:", "").strip()
                            elif line.startswith("ENTITIES:"): entities = line.replace("ENTITIES:", "").strip()
                            elif line.startswith("VICTIMS:"): victims = line.replace("VICTIMS:", "").strip()
                            elif line.startswith("SUMMARY:"): summary = line.replace("SUMMARY:", "").strip()
                        ai_success = True

                if not ai_success: summary = f"Keyword detected. AI Offline (Errors: {last_error[:40]})."

                ss_path = asyncio.run(self.get_screenshot(url, entry_id))
                entry = {
                    "url": url, "intel": summary, "victims": victims, "entities": entities, 
                    "threat": threat, "risk_score": risk_score,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M"), "screenshot": ss_path, "id": entry_id
                }
                
                with self.lock:
                    is_new = write_to_vault(entry)
                    if url not in self.session_found:
                        self.session_found.add(url)
                        self.found_count += 1
                        # Precision Filter: Noise Reduction (Only verify if relevence is confirmed)
                        if risk_score > 15:
                            self.socket.emit('intel_found', entry)
                            if not is_new: self.status(f"Node Re-Verified: {entry_id}", "info")
                            
                            # Phase 13: Trigger Telegram Alert for High Risk
                            if int(entry.get('risk_score', 0)) > 70:
                                self.send_telegram_alert(entry)
                        else:
                            self.status(f"Discarded Low-Relevance Node ({entry_id})", "info")
        except Exception as e:
            if any(s in url for s in ["darkweb", "juhanurmi", "xmh57", "haystak"]):
                self.status(f"CRITICAL: Seed Failure ({url[:20]}) -> {str(e)[:40]}", "warning")

    def run(self):
        # Phase 15: Tor Connection Preflight
        self.status("Performing Tactical Preflight...", "info")
        try:
            r = requests.get("http://check.torproject.org", proxies=TOR_PROXIES, timeout=10)
            if "Congratulations" in r.text:
                self.status("Tor Link Established. Proxy Active.", "success")
            else:
                self.status("Warning: Proxy active but non-Tor exit detected.", "error")
        except Exception as e:
            self.status(f"CRITICAL: Tor Proxy Unreachable (Port 9150). {str(e)[:50]}", "error")
            self.status("Please ensure Tor Browser is running and accessible.", "error")
            time.sleep(2)
            # We continue anyway to allow clear-net discovery if possible
        
        q = self.keyword.replace(" ", "+")
        self.queue = [
            ("https://darkwebdaily.live/", 0),
            (f"http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={q}", 0),
            (f"http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/cgi-bin/omega/omega?P={q}", 0),
            (f"http://haystak5pryel77wvukctp3oih73v65p3zst6ie7u3v567e76n7c4oyd.onion/?q={q}", 0),
        ]

        with ThreadPoolExecutor(max_workers=10) as executor:
            active_futures = []
            while self.found_count < 100: # Increased limit
                if self.stop_event.is_set(): 
                    self.status("ABORTING: Tactical Termination Received.", "error")
                    break
                with self.lock:
                    if not self.queue and not active_futures: break
                    current_batch = []
                    while self.queue and len(current_batch) < 15:
                        current_batch.append(self.queue.pop(0))
                
                if current_batch:
                    active_futures.extend([executor.submit(self.process_url, u, d) for u, d in current_batch])
                
                # Filter out completed futures
                active_futures = [f for f in active_futures if not f.done()]
                time.sleep(1) # Tactful wait for discovery
            
            # Final Buffer: Ensure all async AI hits have been emitted before calling "Done"
            time.sleep(3)

        self.status("Intelligence Scan Complete.", "done")

@dark_web_bp.route('/darkweb')
@login_required
def darkweb_index():
    return render_template('dark_web_views/index.html')

def safe_json_load(data):
    if not data: return []
    try:
        if isinstance(data, str):
            if data.startswith('[') and data.endswith(']'):
                return json.loads(data)
            return [x.strip() for x in data.split(',')]
        return data
    except:
        return []

@dark_web_bp.route('/apt')
@login_required
def apt_dashboard():
    return render_template('dark_web_views/apt_dashboard.html')

@dark_web_bp.route('/api/apt_stats')
def get_apt_stats():
    total_groups = APTGroup.query.count()
    total_links = GroupLink.query.count()
    active_links = GroupLink.query.filter_by(status='ACTIVE').count()
    offline_links = GroupLink.query.filter_by(status='OFFLINE').count()
    
    # Newly discovered in last 24h
    one_day_ago = datetime.now(timezone.utc) - timedelta(days=1)
    new_links = DiscoveryLog.query.filter(DiscoveryLog.timestamp > one_day_ago).count()
    
    return jsonify({
        'total_groups': total_groups,
        'total_links': total_links,
        'active_links': active_links,
        'offline_links': offline_links,
        'new_links': new_links
    })

@dark_web_bp.route('/api/apt_groups')
def get_apt_groups():
    groups = APTGroup.query.all()
    res = []
    for g in groups:
        active_links = sum(1 for l in g.links if l.status == 'ACTIVE')
        offline_links = sum(1 for l in g.links if l.status == 'OFFLINE')
        res.append({
            'id': g.id,
            'name': g.name,
            'country': g.origin_country or 'Unknown',
            'threat': g.threat_level or 'MEDIUM',
            'links': len(g.links),
            'active_links': active_links,
            'offline_links': offline_links,
            'active': active_links > 0,
            'industries': safe_json_load(g.industries),
            'aliases': safe_json_load(g.aliases),
            'description': (g.description or '')[:200],
            'last_activity': g.last_activity.strftime('%Y-%m-%d') if g.last_activity else None,
            'first_seen': g.first_seen or None
        })
    return jsonify(res)

@dark_web_bp.route('/apt/<int:group_id>')
@login_required
def apt_profile(group_id):
    group = APTGroup.query.get_or_404(group_id)
    # Deserialize JSON fields
    group.aliases_list = safe_json_load(group.aliases)
    group.industries_list = safe_json_load(group.industries)
    group.techniques_list = safe_json_load(group.techniques)
    group.tools_list = safe_json_load(group.tools)
    
    # Fetch timeline: latest 10 status changes for this group's links
    link_ids = [l.id for l in group.links]
    timeline = LinkStatusHistory.query.filter(LinkStatusHistory.link_id.in_(link_ids)).order_by(LinkStatusHistory.timestamp.desc()).limit(10).all()
    # Attach URL for summary
    for event in timeline:
        link = next((l for l in group.links if l.id == event.link_id), None)
        event.url_summary = link.url[:40] + "..." if link else "Unknown Node"
    
    group.timeline = timeline
    return render_template('dark_web_views/apt_profile.html', group=group)

@dark_web_bp.route('/download_pdf')
@login_required
def download_pdf():
    # Read from Disk to prevent memory loss
    if not os.path.exists(VAULT_FILE):
        return "<h1>Vault is Empty</h1><p>No results have been saved to the disk yet.</p>", 404
        
    with open(VAULT_FILE, 'r', encoding='utf-8') as f:
        try:
            session_data = json.load(f)
        except:
            return "<h1>Vault Error</h1><p>Could not read data from disk.</p>", 500

    pdf_filename = f"Intel_Report_{int(time.time())}.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = [Paragraph("OFFICIAL CYBER INTELLIGENCE DOSSIER", styles['Title']), Spacer(1, 20)]

    for item in session_data:
        data = [
            [Paragraph(f"<b>SOURCE URL:</b> {item['url']}", styles['Normal'])],
            [Paragraph(f"<b>THREAT LEVEL:</b> {item['threat']} | <b>RISK:</b> {item.get('risk_score', 'N/A')}/100 | <b>TIME:</b> {item['timestamp']}", styles['Normal'])],
            [Paragraph(f"<b>IDENTIFIED VICTIMS:</b> {item['victims']}", styles['Normal'])],
            [Paragraph(f"<b>ENTITIES IDENTIFIED:</b> {item.get('entities', 'None')}", styles['Normal'])],
            [Paragraph(f"<b>AI ANALYSIS:</b><br/>{item['intel']}", styles['Normal'])]
        ]
        
        if item.get('screenshot') and os.path.exists(item['screenshot']):
            try:
                img = Image(item['screenshot'], width=440, height=240)
                data.append([img])
            except: pass

        t = Table(data, colWidths=[480])
        t.setStyle(TableStyle([('BOX', (0,0), (-1,-1), 1, colors.black), ('PADDING', (0,0), (-1,-1), 12)]))
        elements.append(t)
        elements.append(Spacer(1, 25))

    doc.build(elements)
    return send_file(pdf_filename, as_attachment=True)

@socketio.on('clear_vault')
def handle_clear():
    if os.path.exists(VAULT_FILE):
        os.remove(VAULT_FILE)
    with open(VAULT_FILE, 'w', encoding='utf-8') as f:
        json.dump([], f)
    socketio.emit('status_update', {'msg': 'Intelligence Vault Purged.', 'type': 'done'})

@socketio.on('trigger_scan')
def handle_scan(data):
    # We no longer wipe on every scan, allowing persistent history for the PDF
    engine = IntelEngine(data['key'], socketio)
    current_app.active_engine = engine # Store reference for stopping
    threading.Thread(target=engine.run).start()

@socketio.on('stop_scan')
def handle_stop():
    if hasattr(current_app, 'active_engine'):
        current_app.active_engine.stop_event.set()
        socketio.emit('status_update', {'msg': 'TERMINATION SIGNAL DISPATCHED', 'type': 'error'})

# --- New: APT Dynamic Enrichment & Crawling ---

def sanitize_url(url):
    """Remove ALL whitespace and hidden characters (including non-breaking spaces from OCR)."""
    if not url: return ""
    # Remove all whitespace/control chars
    url = re.sub(r'[\s\u200b\u200c\u200d\u200e\u200f\ufeff]+', '', url)
    # Fix common OCR errors in onion parts (Base32 doesn't have I, l, 0, 1, 8, 9)
    # Most onions use lowercase. If we see 'I', it's likely 'l' or meant to be a valid char.
    # But since we don't know the intent, we at least strip weird chars that cause errors.
    return url.strip()

def get_apt_enrichment(group_name):
    """Fetches additional intelligence for an APT group using AI (NVIDIA primary, Gemini fallback)."""
    prompt = (f"Provide a technical dossier for the APT/ransomware group '{group_name}'. "
              f"Include known aliases, target industries, primary techniques (MITRE ATT&CK IDs), and a concise summary of their operations. "
              f"Return ONLY valid JSON in this exact format, no markdown, no extra text: "
              '{"aliases": ["alias1", "alias2"], "industries": ["industry1", "industry2"], "techniques": ["T1059", "T1566"], "summary": "Technical summary here"}')
    
    # --- PRIMARY: NVIDIA Mistral Small ---
    if NVIDIA_API_KEY:
        nvidia_models = ["mistralai/mistral-small-24b-instruct", "mistralai/mistral-small-3.1-24b-instruct-2503"]
        for nvidia_model in nvidia_models:
            try:
                print(f"[AI] Trying NVIDIA model: {nvidia_model} for '{group_name}'")
                url = "https://integrate.api.nvidia.com/v1/chat/completions"
                headers = {"Authorization": f"Bearer {NVIDIA_API_KEY}", "Content-Type": "application/json"}
                payload = {
                    "model": nvidia_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1024, "temperature": 0.1
                }
                resp = requests.post(url, headers=headers, json=payload, timeout=(5, 30))
                print(f"[AI] NVIDIA {nvidia_model} status: {resp.status_code}")
                if resp.status_code == 200:
                    text = resp.json()['choices'][0]['message']['content']
                    print(f"[AI] NVIDIA OK: {text[:80]}...")
                    text = text.strip()
                    if text.startswith("```"):
                        text = re.sub(r'^```(?:json)?\s*', '', text)
                        text = re.sub(r'\s*```$', '', text)
                    match = re.search(r'\{.*\}', text, re.DOTALL)
                    if match:
                        result = json.loads(match.group())
                        print(f"[AI] NVIDIA SUCCESS for '{group_name}'")
                        return result
                elif resp.status_code == 404:
                    print(f"[AI] NVIDIA model {nvidia_model} not found, trying next...")
                    continue
                else:
                    print(f"[AI] NVIDIA FAIL: {resp.status_code} {resp.text[:100]}")
            except Exception as e:
                print(f"[AI] NVIDIA {nvidia_model} ERROR: {type(e).__name__}: {str(e)[:120]}")
                continue
    
    # --- FALLBACK: Gemini ---
    print(f"[AI] NVIDIA exhausted, trying Gemini for '{group_name}'...")
    _gc = get_gemini_client()
    if not _gc:
        print(f"[AI] Gemini skipped — GEMINI_API_KEY not configured.")
        return None
    for model_id in ["gemini-2.0-flash", "gemini-1.5-flash"]:
        try:
            print(f"[AI] Trying Gemini model: {model_id} for '{group_name}'")
            ai_resp = _gc.models.generate_content(model=model_id, contents=prompt)
            text = ai_resp.text
            print(f"[AI] Gemini OK: {text[:80]}...")
            text = text.strip()
            if text.startswith("```"):
                text = re.sub(r'^```(?:json)?\s*', '', text)
                text = re.sub(r'\s*```$', '', text)
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                result = json.loads(match.group())
                print(f"[AI] Gemini SUCCESS for '{group_name}'")
                return result
        except Exception as e:
            print(f"[AI] Gemini {model_id} FAILED: {type(e).__name__}: {str(e)[:80]}")
            continue
    
    print(f"[AI] ALL AI PROVIDERS FAILED for '{group_name}'")
    return None



async def capture_link_screenshot(url, link_id):
    """Playwright helper for specific links."""
    async with async_playwright() as p:
        try:
            # Detect if onion
            proxy = {"server": TOR_SOCKS} if ".onion" in url else None
            browser = await p.chromium.launch(proxy=proxy)
            page = await browser.new_page()
            await page.set_viewport_size({"width": 1280, "height": 720})
            await page.goto(url, timeout=60000, wait_until="commit")
            os.makedirs('static/screenshots', exist_ok=True)
            path = f"static/screenshots/link_{link_id}_{int(time.time())}.png"
            await page.screenshot(path=path)
            await browser.close()
            return path
        except Exception as e:
            print(f"Screenshot error for {url}: {e}")
            return None

def process_apt_crawl(app, group_id, sid):
    with app.app_context():
        group = APTGroup.query.get(group_id)
        if not group: return
        
        socketio.emit('apt_status', {'msg': f"Initializing AI Enrichment for {group.name}...", 'type': 'info'}, room=sid)
        print(f"Enriching Group: {group.name}")
        
        # 1. AI Enrichment
        enrichment = get_apt_enrichment(group.name)
        if enrichment:
            print(f"Enrichment success for {group.name}")
            group.aliases = json.dumps(enrichment.get('aliases', []))
            group.industries = json.dumps(enrichment.get('industries', []))
            group.techniques = json.dumps(enrichment.get('techniques', []))
            group.description = enrichment.get('summary', group.description)
            db.session.commit()
            socketio.emit('group_update', {
                'aliases': enrichment.get('aliases', []),
                'industries': enrichment.get('industries', []),
                'techniques': enrichment.get('techniques', []),
                'description': group.description
            }, room=sid)
        else:
            print(f"Enrichment failed for {group.name}")

        # 2. Link Crawling
        for link in group.links:
            clean_url = sanitize_url(link.url)
            socketio.emit('link_crawl_status', {'link_id': link.id, 'status': 'SCANNING...'}, room=sid)
            
            start_time = time.time()
            is_online = False
            status_code = None
            try:
                # Use localhost as it is more stable on some Windows Tor installations
                prox = TOR_PROXIES_LH if ".onion" in clean_url else None
                # Global SSL bypass to prevent getaddrinfo failures and cert errors
                r = requests.get(clean_url, proxies=prox, timeout=20, 
                                 headers={'User-Agent': 'Mozilla/5.0'},
                                 verify=False)
                is_online = r.status_code == 200
                status_code = r.status_code
            except: is_online = False
            
            response_time = time.time() - start_time
            link.status = 'ACTIVE' if is_online else 'OFFLINE'
            link.last_active = datetime.now(timezone.utc)
            link.response_time = response_time
            link.status_code = status_code
            
            # Record History
            history = LinkStatusHistory(link_id=link.id, status=link.status, response_time=response_time)
            db.session.add(history)
            
            # Screenshot if Online
            screenshot_path = None
            if is_online:
                screenshot_path = asyncio.run(capture_link_screenshot(clean_url, link.id))
                if screenshot_path:
                    # Save to DB - Link to GroupLink
                    from backend.models import Screenshot
                    ss = Screenshot(link_id=link.id, path=screenshot_path)
                    db.session.add(ss)
            
            db.session.commit()
            
            socketio.emit('link_update', {
                'link_id': link.id,
                'status': link.status,
                'last_active': link.last_active.strftime('%Y-%m-%d %H:%M:%S'),
                'screenshot': screenshot_path
            }, room=sid)

        socketio.emit('apt_status', {'msg': "Live Intelligence Scan Complete.", 'type': 'done'}, room=sid)

@socketio.on('start_apt_crawl')
def handle_apt_crawl(data):
    group_id = data.get('group_id')
    app = current_app._get_current_object()
    threading.Thread(target=process_apt_crawl, args=(app, group_id, request.sid)).start()

def process_all_apt_crawl(app, sid):
    """Crawl ALL APT groups' links and emit real-time updates to the dashboard."""
    with app.app_context():
        # Quick Tor connectivity check first
        tor_available = False
        try:
            r = requests.get("http://check.torproject.org", proxies=TOR_PROXIES, timeout=8)
            tor_available = "Congratulations" in r.text
        except:
            pass

        if not tor_available:
            print("[CRAWL-ALL] WARNING: Tor proxy not reachable on port 9150. .onion links will be skipped.")
            socketio.emit('dash_status', {'msg': 'Tor proxy offline — scanning clearnet links only.', 'type': 'warning', 'total': 0}, room=sid)

        groups = APTGroup.query.all()
        total = len(groups)
        print(f"[CRAWL-ALL] Starting scan of {total} groups (Tor: {'YES' if tor_available else 'NO'})")
        socketio.emit('dash_status', {'msg': f'Starting live scan of {total} APT groups...', 'type': 'info', 'total': total}, room=sid)

        online_count = 0
        offline_count = 0

        for idx, group in enumerate(groups):
            socketio.emit('dash_status', {'msg': f'Scanning {group.name} ({idx+1}/{total})...', 'type': 'info', 'progress': idx+1, 'total': total}, room=sid)

            # AI Enrichment (skip if already enriched)
            if not group.description or group.description.startswith('Persistent threat actor'):
                enrichment = get_apt_enrichment(group.name)
                if enrichment:
                    group.aliases = json.dumps(enrichment.get('aliases', []))
                    group.industries = json.dumps(enrichment.get('industries', []))
                    group.techniques = json.dumps(enrichment.get('techniques', []))
                    group.description = enrichment.get('summary', group.description)
                    db.session.commit()

            # Crawl each link
            screenshot_path = None
            for link in group.links:
                clean_url = sanitize_url(link.url)
                is_onion = ".onion" in clean_url

                # Skip .onion links if Tor isn't available
                if is_onion and not tor_available:
                    link.status = 'OFFLINE'
                    link.last_active = datetime.now(timezone.utc)
                    link.response_time = 0
                    offline_count += 1
                    db.session.commit()
                    continue

                start_time = time.time()
                is_online = False
                status_code = None
                try:
                    prox = TOR_PROXIES_LH if is_onion else None
                    tout = 20 if is_onion else 10
                    r = requests.get(clean_url, proxies=prox, timeout=tout, 
                                     headers={'User-Agent': 'Mozilla/5.0'}, 
                                     verify=False)
                    is_online = r.status_code == 200
                    status_code = r.status_code
                except Exception as e:
                    is_online = False

                response_time = time.time() - start_time
                link.status = 'ACTIVE' if is_online else 'OFFLINE'
                link.last_active = datetime.now(timezone.utc)
                link.response_time = response_time
                link.status_code = status_code

                if is_online:
                    online_count += 1
                else:
                    offline_count += 1

                history = LinkStatusHistory(link_id=link.id, status=link.status, response_time=response_time)
                db.session.add(history)

                if is_online:
                    try:
                        screenshot_path = asyncio.run(capture_link_screenshot(clean_url, link.id))
                        if screenshot_path:
                            from backend.models import Screenshot as SS
                            db.session.add(SS(link_id=link.id, path=screenshot_path))
                    except Exception as e:
                        print(f"[CRAWL-ALL]   Screenshot failed: {e}")

                db.session.commit()

            # Emit per-group update to dashboard
            active_links = sum(1 for l in group.links if l.status == 'ACTIVE')
            socketio.emit('dash_group_update', {
                'group_id': group.id,
                'name': group.name,
                'active': active_links > 0,
                'active_links': active_links,
                'country': group.origin_country or 'Unknown',
                'threat': group.threat_level or 'MEDIUM',
                'industries': safe_json_load(group.industries),
                'aliases': safe_json_load(group.aliases),
                'description': (group.description or '')[:200],
                'links': len(group.links),
                'screenshot': screenshot_path
            }, room=sid)

        print(f"[CRAWL-ALL] Scan complete: {online_count} online, {offline_count} offline out of {total} groups")
        socketio.emit('dash_status', {'msg': f'Scan Complete — {online_count} online, {offline_count} offline.', 'type': 'done', 'progress': total, 'total': total}, room=sid)

@socketio.on('start_all_apt_crawl')
def handle_all_apt_crawl():
    app = current_app._get_current_object()
    threading.Thread(target=process_all_apt_crawl, args=(app, request.sid)).start()

