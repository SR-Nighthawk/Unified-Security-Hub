from datetime import datetime
from backend.extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class APTGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    aliases = db.Column(db.Text) # JSON string
    origin_country = db.Column(db.String(100))
    industries = db.Column(db.Text) # JSON string
    techniques = db.Column(db.Text) # MITRE ATT&CK Info
    description = db.Column(db.Text)
    tools = db.Column(db.Text)
    first_seen = db.Column(db.String(50))
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    threat_level = db.Column(db.String(20), default="MEDIUM") # LOW, MEDIUM, HIGH, CRITICAL
    
    links = db.relationship('GroupLink', backref='group', lazy=True)

class GroupLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('apt_group.id'), nullable=False)
    url = db.Column(db.String(500), unique=True, nullable=False)
    type = db.Column(db.String(50)) # onion, web, leak
    status = db.Column(db.String(20), default="UNKNOWN") # ACTIVE, OFFLINE, UNKNOWN
    last_active = db.Column(db.DateTime)
    response_time = db.Column(db.Float)
    status_code = db.Column(db.Integer)
    title = db.Column(db.String(200))

class LinkStatusHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey('group_link.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20))
    response_time = db.Column(db.Float)

class Screenshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey('group_link.id'), nullable=False)
    path = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class DiscoveryLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), unique=True)
    source = db.Column(db.String(200)) # RSS, Github, Blog
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_new = db.Column(db.Boolean, default=True)
    assigned_group_id = db.Column(db.Integer, db.ForeignKey('apt_group.id'))

# ─── RANSOMWARE.LIVE INTEGRATION MODELS ─────────────────────────────────────

class RansomwareVictim(db.Model):
    """Stores victim disclosures fetched from Ransomware.live Pro API."""
    id = db.Column(db.String(100), primary_key=True)  # API-provided ID
    name = db.Column(db.String(300))
    group_name = db.Column(db.String(100))
    country = db.Column(db.String(10))
    sector = db.Column(db.String(100))
    description = db.Column(db.Text)
    discovered = db.Column(db.DateTime)
    website = db.Column(db.String(300))
    ransomware_group_id = db.Column(db.Integer, db.ForeignKey('ransomware_group.id'), nullable=True)
    infostealer = db.Column(db.Boolean, default=False)
    ransom_amount = db.Column(db.Float, nullable=True)
    post_url = db.Column(db.String(500), nullable=True)  # Onion Link
    screenshot = db.Column(db.String(500), nullable=True) # Proof
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'group_name': self.group_name,
            'country': self.country,
            'sector': self.sector,
            'description': self.description,
            'discovered': self.discovered.strftime('%Y-%m-%d %H:%M') if self.discovered else None,
            'website': self.website,
            'infostealer': self.infostealer,
            'post_url': self.post_url,
            'screenshot': self.screenshot,
        }

class RansomwareGroup(db.Model):
    """Stores ransomware group metadata from Ransomware.live."""
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    slug = db.Column(db.String(100), unique=True, nullable=False)  # e.g. "lockbit5"
    name = db.Column(db.String(200))
    description = db.Column(db.Text)
    status = db.Column(db.String(50))          # active, inactive
    first_seen = db.Column(db.String(50))
    last_seen = db.Column(db.String(50))
    victim_count = db.Column(db.Integer, default=0)
    threat_level = db.Column(db.String(20), default='MEDIUM')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    victims = db.relationship('RansomwareVictim', backref='ransomware_group', lazy=True,
                               foreign_keys='RansomwareVictim.ransomware_group_id')

    def to_dict(self):
        return {
            'id': self.id,
            'slug': self.slug,
            'name': self.name,
            'status': self.status,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'victim_count': self.victim_count,
            'threat_level': self.threat_level,
        }

class RansomwareWatchlist(db.Model):
    """User-defined rules for ransomware victim alerts."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    filter_sector = db.Column(db.String(100))    # e.g. "Healthcare"
    filter_country = db.Column(db.String(10))    # e.g. "IN", "US"
    filter_group = db.Column(db.String(100))     # e.g. "lockbit5"
    filter_keyword = db.Column(db.String(200))   # keyword in victim name/description
    alert_telegram = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
