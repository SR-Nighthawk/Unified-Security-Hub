import os, re

src = r"C:\Users\test\Downloads\SUMIT PROJECT\dark_web\app.py"
dst = r"C:\Users\test\Downloads\SUMIT PROJECT\Unified_Security_Hub\backend\dark_web_logic\routes.py"

with open(src, 'r', encoding='utf-8') as f:
    code = f.read()

# Replace global app setup block
old_app_block = """app = Flask(__name__, template_folder='templates', static_folder='static')
db_path = os.path.join(os.getcwd(), 'apt_intel.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')"""

new_app_block = """from flask import Blueprint, current_app
from backend.extensions import socketio, db

dark_web_bp = Blueprint('dark_web_bp', __name__)"""
code = code.replace(old_app_block, new_app_block)

code = code.replace("from models import db, APTGroup, GroupLink, LinkStatusHistory, DiscoveryLog", "from backend.models import APTGroup, GroupLink, LinkStatusHistory, DiscoveryLog")
code = code.replace("from apt_worker import start_scheduler", "from backend.apt_worker import start_scheduler")
code = code.replace("from models import Screenshot", "from backend.models import Screenshot")

# Route replacements
code = re.sub(r'@app\.route', r'@dark_web_bp.route', code)

# Fix context issues
code = code.replace("app.active_engine = engine", "current_app.active_engine = engine")
code = code.replace("hasattr(app, 'active_engine')", "hasattr(current_app, 'active_engine')")
code = code.replace("app.active_engine.stop_event.set()", "current_app.active_engine.stop_event.set()")
code = code.replace("with app.app_context():", "with current_app.app_context():")

# Main block remove
code = re.sub(r"if __name__ == '__main__':.*", "", code, flags=re.DOTALL)

with open(dst, 'w', encoding='utf-8') as f:
    f.write(code)

print('Routes refactored.')
