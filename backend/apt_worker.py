import os, time, requests, json, asyncio, re
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from backend.models import db, APTGroup, GroupLink, LinkStatusHistory, DiscoveryLog, Screenshot
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
from backend.core.config import TOR_PROXIES, TOR_SOCKS_URL

def sanitize_url(url):
    """Remove ALL whitespace and hidden characters (including non-breaking spaces from OCR)."""
    if not url: return ""
    # Remove all whitespace/control chars
    url = re.sub(r'[\s\u200b\u200c\u200d\u200e\u200f\ufeff]+', '', url)
    return url.strip()

# Tor Configuration — sourced from centralized config
TOR_PROXIES_LH = TOR_PROXIES
TOR_SOCKS = TOR_SOCKS_URL

async def capture_screenshot(url, link_id):
    """Captures a screenshot of the onion link via Playwright and Tor."""
    async with async_playwright() as p:
        try:
            # Re-use proxy settings from app config
            browser = await p.chromium.launch(proxy={"server": TOR_SOCKS})
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; rv:120.0) Gecko/20100101 Firefox/120.0"
            )
            page = await context.new_page()
            await page.set_viewport_size({"width": 1280, "height": 720})
            
            # Navigate with long timeout for onion links
            await page.goto(url, timeout=90000, wait_until="networkidle")
            
            # Create screenshot directory if missing
            os.makedirs('static/screenshots', exist_ok=True)
            path = f"static/screenshots/node_{link_id}_{int(time.time())}.png"
            await page.screenshot(path=path)
            await browser.close()
            return path
        except Exception as e:
            print(f"Screenshot failed for {url}: {e}")
            return None

def check_link_status(app, specific_link_id=None):
    with app.app_context():
        if specific_link_id:
            links = GroupLink.query.filter_by(id=specific_link_id).all()
        else:
            links = GroupLink.query.all()
            
        # Group by actor for dashboard updates
        actor_updates = {}
        
        for link in links:
            try:
                clean_url = sanitize_url(link.url)
                start_time = time.time()
                # Use localhost for stability
                proxies = TOR_PROXIES_LH if ".onion" in clean_url else None
                # Global SSL bypass
                response = requests.get(clean_url, proxies=proxies, timeout=40, verify=False)
                resp_time = time.time() - start_time
                
                status = "ACTIVE" if response.status_code == 200 else "OFFLINE"
                
                # Update Link
                link.status = status
                link.last_active = datetime.utcnow() if status == "ACTIVE" else link.last_active
                link.response_time = resp_time
                link.status_code = response.status_code
                
                # Extract Title
                soup = BeautifulSoup(response.text, 'html.parser')
                link.title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"

                # Log History
                history = LinkStatusHistory(link_id=link.id, status=status, response_time=resp_time)
                db.session.add(history)
                
                # Capture Screenshot if ACTIVE
                ss_path = None
                if status == "ACTIVE":
                    ss_path = asyncio.run(capture_screenshot(clean_url, link.id))
                    if ss_path:
                        ss_entry = Screenshot(link_id=link.id, path=ss_path)
                        db.session.add(ss_entry)
                
                # Track for dashboard
                group = link.group
                if group.id not in actor_updates:
                    actor_updates[group.id] = {
                        'group_id': group.id,
                        'active': False,
                        'country': group.origin_country or 'Unknown',
                        'threat': group.threat_level or 'MEDIUM',
                        'industries': json.loads(group.industries) if group.industries else [],
                        'aliases': json.loads(group.aliases) if group.aliases else [],
                        'links': len(group.links),
                        'screenshot': ss_path
                    }
                if status == "ACTIVE":
                    actor_updates[group.id]['active'] = True
                
                # Notify individual node view
                if hasattr(app, 'socketio'):
                    app.socketio.emit('node_update', {
                        'id': link.id,
                        'status': status,
                        'resp_time': f"{resp_time:.2f}s",
                        'title': link.title,
                        'screenshot': ss_path
                    })

            except Exception as e:
                link.status = "OFFLINE"
                print(f"Link Offline: {link.url} -> {str(e)[:50]}")
            
            db.session.commit()
            
        # Emit dashboard summary updates
        if hasattr(app, 'socketio'):
            for upd in actor_updates.values():
                app.socketio.emit('dash_group_update', upd)
                
        print(f"[{datetime.now()}] Link Health Check Completed.")

def discover_new_links(app):
    with app.app_context():
        print(f"[{datetime.now()}] Starting Intelligence Discovery Engine...")
        # Mock discovery logic
        print(f"[{datetime.now()}] Discovery Engine Pulse Complete.")

def start_scheduler(app):
    scheduler = BackgroundScheduler()
    # Link health check every 6 hours (not on startup — use manual "Scan All" button)
    scheduler.add_job(func=check_link_status, trigger="interval", seconds=21600, args=[app])
    # Discovery engine every 24 hours
    scheduler.add_job(func=discover_new_links, trigger="interval", seconds=86400, args=[app])
    
    # ─── NEW: Ransomware.live jobs ────────────────────────────────────────────
    def ransomware_victim_job():
        """Runs inside app context — fetches and stores latest victims."""
        with app.app_context():
            from backend.modules.ransomware_module import ingest_victims
            ingest_victims(limit=100)

    def ransomware_groups_job():
        """Runs inside app context — fetches and upserts all group metadata."""
        with app.app_context():
            from backend.modules.ransomware_module import ingest_groups
            ingest_groups()

    # Victims: every 15 minutes
    scheduler.add_job(func=ransomware_victim_job, trigger="interval", seconds=900)
    # Groups: every 6 hours
    scheduler.add_job(func=ransomware_groups_job, trigger="interval", seconds=21600)
    # ──────────────────────────────────────────────────────────────────────────
    
    scheduler.start()
    print("APT Scheduler Initialized.")
