import re
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from backend.models import User
from backend.extensions import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('auth.html')

@auth_bp.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json
    email = data.get('email', '').strip()
    password = data.get('password', '')

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        login_user(user)
        return jsonify({"success": True, "redirect": url_for('dashboard')})
    
    return jsonify({"success": False, "error": "Invalid email or password"}), 401

@auth_bp.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.json
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({"success": False, "error": "All fields are required"}), 400

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"success": False, "error": "Invalid email address"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"success": False, "error": "Email already registered"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"success": False, "error": "Username already taken"}), 400

    new_user = User(username=username, email=email)
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()

    # Auto-login upon successful registration
    login_user(new_user)
    
    return jsonify({"success": True, "redirect": url_for('dashboard')})

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('landing_page'))

@auth_bp.route('/profile')
@login_required
def profile_page():
    return render_template('profile.html', user=current_user)
