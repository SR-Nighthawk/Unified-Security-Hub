import os
import requests
import json
from datetime import datetime
from flask import Blueprint, jsonify, render_template, request
from backend.extensions import db
from backend.models import RansomwareVictim, RansomwareGroup, RansomwareWatchlist
from dotenv import load_dotenv

load_dotenv()

ransomware_bp = Blueprint('ransomware', __name__)

API_KEY = os.getenv("RANSOMWARE_LIVE_API_KEY")
BASE_URL = os.getenv("RANSOMWARE_LIVE_BASE_URL", "https://api.ransomware.live/v2")
TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TG_CHAT = os.getenv("TELEGRAM_CHAT_ID")

HEADERS = {
    "X-Api-Key": API_KEY,
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
}

# ─── API CLIENT ─────────────────────────────────────────────────────────────

def rl_get(endpoint, params=None, timeout=30):
    """Generic GET wrapper for Ransomware.live Pro API."""
    try:
        r = requests.get(f"{BASE_URL}{endpoint}", headers=HEADERS, params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[RansomWatch] API error ({endpoint}): {e}")
        return None

# ─── DATA INGESTION ──────────────────────────────────────────────────────────

def ingest_victims(data_source=None):
    """Fetch recent victims and store new ones in the DB. Returns count of new records."""
    if data_source is None:
        data = rl_get("/victims/recent", params={"limit": 100})
        if not data:
            return 0
        victims = data if isinstance(data, list) else data.get("victims", [])
    else:
        victims = data_source
        
    new_count = 0

    for v in victims:
        if not isinstance(v, dict):
            continue
            
        victim_id = v.get("id") or v.get("post_id") or ""
        if not victim_id:
            continue

        existing = RansomwareVictim.query.get(victim_id)
        if existing:
            # Resolve group FK
            group_slug = v.get("group_name", "").lower().replace(" ", "")
            existing.country = v.get("country") or existing.country
            existing.sector = v.get("activity") or existing.sector
            existing.website = v.get("website") or existing.website
            existing.infostealer = bool(v.get("infostealer", {}))
            existing.post_url = v.get("post_url") or existing.post_url
            existing.screenshot = v.get("screenshot") or existing.screenshot
            continue
        else:
            try:
                dt = datetime.strptime(v.get("discovered", ""), "%Y-%m-%d %H:%M:%S.%f")
            except:
                dt = datetime.utcnow()
                
            victim = RansomwareVictim(
                id=victim_id,
                name=v.get("victim", ""),
                group_name=v.get("group", ""),
                country=v.get("country", ""),
                sector=v.get("activity", ""),
                description=v.get("description", ""),
                discovered=dt,
                website=v.get("website", ""),
                infostealer=bool(v.get("infostealer", {})),
                post_url=v.get("post_url", ""),
                screenshot=v.get("screenshot", "")
            )
            db.session.add(victim)
            new_count += 1

            # Check watchlists
            trigger_watchlist_alerts(victim)

    db.session.commit()
    print(f"[RansomWatch] Ingested {new_count} new victims.")
    return new_count


def ingest_groups():
    """Fetch all ransomware groups and upsert into DB."""
    data = rl_get("/groups")
    if not data:
        return 0

    groups = data if isinstance(data, list) else data.get("groups", [])
    count = 0
    for g in groups:
        if not isinstance(g, dict):
            continue
            
        slug = (g.get("group") or g.get("name") or "").lower().replace(" ", "")
        if not slug:
            continue

        existing = RansomwareGroup.query.filter_by(slug=slug).first()
        if existing:
            existing.name = g.get("group") or g.get("name") or existing.name
            existing.victim_count = g.get("victims") or g.get("nb_victims") or existing.victim_count
            existing.last_seen = g.get("last_post_date") or existing.last_seen
            existing.status = "active" if g.get("victims", 0) > 0 else "inactive"
            existing.updated_at = datetime.utcnow()
        else:
            rg = RansomwareGroup(
                slug=slug,
                name=g.get("group") or g.get("name", slug),
                description=(g.get("description") or "")[:500],
                status="active" if g.get("victims", 0) > 0 else "inactive",
                first_seen=(g.get("meta") or {}).get("first_seen", ""),
                last_seen=g.get("last_post_date", ""),
                victim_count=g.get("victims") or g.get("nb_victims", 0),
            )
            db.session.add(rg)
            count += 1

    db.session.commit()
    print(f"[RansomWatch] Upserted groups. {count} new.")
    return count

# ─── WATCHLIST ALERTING ──────────────────────────────────────────────────────

def trigger_watchlist_alerts(victim: RansomwareVictim):
    """Check a new victim against all active watchlist rules and send Telegram alerts."""
    rules = RansomwareWatchlist.query.filter_by(is_active=True).all()
    for rule in rules:
        matched = False

        if rule.filter_sector and rule.filter_sector.lower() in (victim.sector or "").lower():
            matched = True
        if rule.filter_country and rule.filter_country.upper() == (victim.country or "").upper():
            matched = True
        if rule.filter_group and rule.filter_group.lower() in (victim.group_name or "").lower():
            matched = True
        if rule.filter_keyword and rule.filter_keyword.lower() in (
            (victim.name or "") + " " + (victim.description or "")
        ).lower():
            matched = True

        if matched and rule.alert_telegram and TG_TOKEN and TG_CHAT:
            send_telegram_ransomware_alert(victim, rule)


def send_telegram_ransomware_alert(victim: RansomwareVictim, rule: RansomwareWatchlist):
    """Send a Telegram message for a watchlist match."""
    msg = (
        f"🔴 RANSOMWARE ALERT — {rule.name}\n\n"
        f"Victim: {victim.name}\n"
        f"Group: {victim.group_name}\n"
        f"Sector: {victim.sector or 'Unknown'}\n"
        f"Country: {victim.country or 'Unknown'}\n"
        f"Discovered: {victim.discovered}\n"
    )
    try:
        url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": TG_CHAT, "text": msg}, timeout=10)
    except Exception as e:
        print(f"[RansomWatch] Telegram alert failed: {e}")

# ─── PAGE ROUTES ─────────────────────────────────────────────────────────────

@ransomware_bp.route("/ransomware")
def ransomware_dashboard():
    return render_template("ransomware_views/dashboard.html")

@ransomware_bp.route("/ransomware/victims")
def ransomware_victims():
    return render_template("ransomware_views/victims.html")

@ransomware_bp.route("/ransomware/groups")
def ransomware_groups():
    return render_template("ransomware_views/groups.html")

@ransomware_bp.route("/ransomware/watchlist")
def ransomware_watchlist():
    return render_template("ransomware_views/watchlist.html")

@ransomware_bp.route("/ransomware/ioc")
def ransomware_ioc_ui():
    return render_template("ransomware_views/iocs.html")

# ─── JSON API ROUTES ─────────────────────────────────────────────────────────

@ransomware_bp.route("/api/ransomware/stats")
def api_ransomware_stats():
    """Summary stats for the dashboard widget."""
    total_victims = RansomwareVictim.query.count()
    total_groups = RansomwareGroup.query.count()

    from datetime import timedelta
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_victims = RansomwareVictim.query.filter(RansomwareVictim.discovered >= week_ago).count()

    from sqlalchemy import func
    top_sector = (
        db.session.query(RansomwareVictim.sector, func.count(RansomwareVictim.sector).label("cnt"))
        .group_by(RansomwareVictim.sector)
        .order_by(func.count(RansomwareVictim.sector).desc())
        .first()
    )

    top_group = (
        db.session.query(RansomwareVictim.group_name, func.count(RansomwareVictim.group_name).label("cnt"))
        .group_by(RansomwareVictim.group_name)
        .order_by(func.count(RansomwareVictim.group_name).desc())
        .first()
    )

    recent_feed = [v.to_dict() for v in
                   RansomwareVictim.query.order_by(RansomwareVictim.discovered.desc()).limit(5).all()]

    return jsonify({
        "total_victims": total_victims,
        "total_groups": total_groups,
        "victims_this_week": recent_victims,
        "top_sector": top_sector[0] if top_sector else "N/A",
        "top_group": top_group[0] if top_group else "N/A",
        "recent_feed": recent_feed,
    })

@ransomware_bp.route("/api/ransomware/victims")
def api_ransomware_victims():
    """Paginated victim list with optional filters."""
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    group = request.args.get("group")
    country = request.args.get("country")
    sector = request.args.get("sector")

    q = RansomwareVictim.query.order_by(RansomwareVictim.discovered.desc())
    if group:
        q = q.filter(RansomwareVictim.group_name.ilike(f"%{group}%"))
    if country:
        q = q.filter(RansomwareVictim.country == country.upper())
    if sector:
        q = q.filter(RansomwareVictim.sector.ilike(f"%{sector}%"))

    paginated = q.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        "victims": [v.to_dict() for v in paginated.items],
        "total": paginated.total,
        "page": page,
        "pages": paginated.pages,
    })

@ransomware_bp.route("/api/ransomware/groups")
def api_ransomware_groups():
    groups = RansomwareGroup.query.order_by(RansomwareGroup.victim_count.desc()).all()
    return jsonify([g.to_dict() for g in groups])

@ransomware_bp.route("/api/ransomware/refresh", methods=["POST"])
def api_ransomware_refresh():
    """Manual sync triggered from the UI. Backfills aggressive history."""
    try:
        # Fetching for entire 2026 to populate massive data instead of just 100 recent rows
        data = rl_get("/victims/?year=2026", timeout=120)
        victims = data if isinstance(data, list) else data.get("victims", [])
        
        # If the API returned nothing or errored, fallback to scraping recent to be safe
        if not victims:
            recent_data = rl_get("/victims/recent")
            victims = recent_data if isinstance(recent_data, list) else recent_data.get("victims", [])

        v_count = ingest_victims(victims)
        g_count = ingest_groups()
        return jsonify({
            "success": True,
            "new_victims": len(victims),  # Update UI explicitly regarding payload size fetched
            "new_groups": g_count,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ─── WATCHLIST CRUD ──────────────────────────────────────────────────────────

@ransomware_bp.route("/api/ransomware/watchlist", methods=["GET"])
def get_watchlist():
    rules = RansomwareWatchlist.query.order_by(RansomwareWatchlist.created_at.desc()).all()
    return jsonify([{
        "id": r.id, "name": r.name,
        "filter_sector": r.filter_sector, "filter_country": r.filter_country,
        "filter_group": r.filter_group, "filter_keyword": r.filter_keyword,
        "alert_telegram": r.alert_telegram, "is_active": r.is_active,
    } for r in rules])

@ransomware_bp.route("/api/ransomware/watchlist", methods=["POST"])
def create_watchlist():
    d = request.json
    rule = RansomwareWatchlist(
        name=d.get("name", "My Alert"),
        filter_sector=d.get("filter_sector"),
        filter_country=d.get("filter_country"),
        filter_group=d.get("filter_group"),
        filter_keyword=d.get("filter_keyword"),
        alert_telegram=d.get("alert_telegram", False),
    )
    db.session.add(rule)
    db.session.commit()
    return jsonify({"success": True, "id": rule.id})

@ransomware_bp.route("/api/ransomware/watchlist/<int:rule_id>", methods=["DELETE"])
def delete_watchlist(rule_id):
    rule = RansomwareWatchlist.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    return jsonify({"success": True})

# ─── LIVE API PROXY (optional: for IoC, YARA, TTPs, Negotiations) ────────────

@ransomware_bp.route("/api/ransomware/ioc")
def api_ransomware_ioc():
    """Proxy for IoC."""
    return jsonify(rl_get("/iocs") or [])

@ransomware_bp.route("/api/ransomware/ioc/<group>")
def api_ransomware_ioc_group(group):
    """Proxy for specific IoC."""
    return jsonify(rl_get(f"/iocs/{group}") or [])

@ransomware_bp.route("/api/ransomware/group/<slug>")
def api_ransomware_group_detail(slug):
    """Proxy for Threat Group detail dossier."""
    return jsonify(rl_get(f"/group/{slug}") or {})

@ransomware_bp.route("/api/ransomware/yara")
def api_yara():
    data = rl_get("/yara")
    return jsonify(data or [])

@ransomware_bp.route("/api/ransomware/negotiations")
def api_negotiations():
    data = rl_get("/negotiations")
    return jsonify(data or [])
