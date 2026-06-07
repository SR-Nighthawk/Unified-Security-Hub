import os
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_login import LoginManager

db = SQLAlchemy()

# async_mode: 'eventlet' for production (Gunicorn), 'threading' for local dev
# Set SOCKETIO_ASYNC_MODE=threading in .env for local Windows development
_async_mode = os.getenv("SOCKETIO_ASYNC_MODE", "eventlet")
socketio = SocketIO(cors_allowed_origins="*", async_mode=_async_mode)

login_manager = LoginManager()
login_manager.login_view = 'auth.login_page'
login_manager.login_message_category = 'warning'
