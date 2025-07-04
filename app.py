import os
import secrets
import hashlib
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, abort, Response, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16) # Change this to a strong, random key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../instance/iptv.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Database Models ---

class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode('utf-8')).hexdigest()

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    is_banned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to store connected IPs for this token
    connected_ips = db.relationship('ConnectedIP', backref='token', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Token {self.token}>'

class ConnectedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('token.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False) # IPv4 or IPv6
    last_access = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ConnectedIP {self.ip_address} for Token {self.token_id}>'

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    token = db.Column(db.String(255), nullable=True) # Store token string for easier lookup
    user_agent = db.Column(db.Text, nullable=True)
    referrer = db.Column(db.Text, nullable=True)
    status_code = db.Column(db.Integer, nullable=True) # E.g., 200 for success, 403 for blocked

    def __repr__(self):
        return f'<AccessLog {self.ip_address} at {self.timestamp}>'

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    stream_url = db.Column(db.Text, nullable=False)
    logo_url = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Channel {self.name}>'

# --- Database Initialization (Run once) ---
@app.before_first_request
def create_tables():
    db.create_all()
    # Create a default admin user if one doesn't exist
    if not AdminUser.query.filter_by(username='admin').first():
        admin = AdminUser(username='admin')
        admin.set_password('adminpassword') # CHANGE THIS PASSWORD IMMEDIATELY IN PRODUCTION
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created: username='admin', password='adminpassword'")

# --- Helper Functions ---
def is_logged_in():
    return 'logged_in' in session and session['logged_in']

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_random_token(length=32):
    return secrets.token_urlsafe(length)

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin_user = AdminUser.query.filter_by(username=username).first()

        if admin_user and admin_user.check_password(password):
            session['logged_in'] = True
            session['username'] = admin_user.username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin_panel():
    tokens = Token.query.all()
    channels = Channel.query.all()
    # To get the count of connected IPs directly from the relationship
    # No need for a separate query here if ConnectedIP is correctly related
    access_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(100).all() # Show last 100 logs

    # Calculate number of connected IPs for each token (more recent IPs)
    token_ip_counts = {}
    for token_obj in tokens:
        # Only consider IPs that have accessed the playlist recently (e.g., in the last 24 hours)
        # This prevents old IPs from perpetually counting towards the limit if not actively streaming.
        # Adjust the timedelta as per your "active" IP definition.
        recent_ips = ConnectedIP.query.filter(
            ConnectedIP.token_id == token_obj.id,
            ConnectedIP.last_access >= datetime.utcnow() - timedelta(days=1)
        ).group_by(ConnectedIP.ip_address).all()
        token_ip_counts[token_obj.id] = len(recent_ips)

    return render_template('admin.html',
                           tokens=tokens,
                           channels=channels,
                           access_logs=access_logs,
                           token_ip_counts=token_ip_counts,
                           current_time=datetime.utcnow())

# --- Token Management ---

@app.route('/admin/add_token', methods=['POST'])
@admin_required
def add_token():
    try:
        expiry_days = int(request.form['expiry_days'])
        token_str = request.form.get('token', generate_random_token())
        if Token.query.filter_by(token=token_str).first():
            flash('Token already exists. Please choose a different one or leave blank for auto-generation.', 'danger')
            return redirect(url_for('admin_panel'))

        expiry_date = datetime.utcnow() + timedelta(days=expiry_days)
        new_token = Token(token=token_str, expiry=expiry_date)
        db.session.add(new_token)
        db.session.commit()
        flash('Token added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding token: {e}', 'danger')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_token/<int:token_id>')
@admin_required
def delete_token(token_id):
    token = Token.query.get_or_404(token_id)
    try:
        db.session.delete(token)
        db.session.commit()
        flash('Token deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting token: {e}', 'danger')
    return redirect(url_for('admin_panel'))

@app.route('/admin/reset_ips/<int:token_id>')
@admin_required
def reset_ips(token_id):
    token = Token.query.get_or_404(token_id)
    try:
        ConnectedIP.query.filter_by(token_id=token.id).delete()
        db.session.commit()
        flash(f'Connected IPs for token "{token.token}" reset!', 'success')
    except Exception as e:
        flash(f'Error resetting IPs: {e}', 'danger')
    return redirect(url_for('admin_panel'))

@app.route('/admin/renew_token/<int:token_id>', methods=['POST'])
@admin_required
def renew_token(token_id):
    token = Token.query.get_or_404(token_id)
    try:
        renew_days = int(request.form['renew_days'])
        token.expiry = token.expiry + timedelta(days=renew_days)
        db.session.commit()
        flash(f'Token "{token.token}" renewed for {renew_days} days!', 'success')
    except Exception as e:
        flash(f'Error renewing token: {e}', 'danger')
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle_ban_token/<int:token_id>')
@admin_required
def toggle_ban_token(token_id):
    token = Token.query.get_or_404(token_id)
    try:
        token.is_banned = not token.is_banned
        db.session.commit()
        status = "banned" if token.is_banned else "unbanned"
        flash(f'Token "{token.token}" has been {status}!', 'success')
    except Exception as e:
        flash(f'Error toggling ban status: {e}', 'danger')
    return redirect(url_for('admin_panel'))

# --- Channel Management ---

@app.route('/admin/add_channel', methods=['POST'])
@admin_required
def add_channel():
    try:
        name = request.form['name']
        stream_url = request.form['stream_url']
        logo_url = request.form.get('logo_url', '')

        new_channel = Channel(name=name, stream_url=stream_url, logo_url=logo_url)
        db.session.add(new_channel)
        db.session.commit()
        flash('Channel added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding channel: {e}', 'danger')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_channel/<int:channel_id>')
@admin_required
def delete_channel(channel_id):
    channel = Channel.query.get_or_404(channel_id)
    try:
        db.session.delete(channel)
        db.session.commit()
        flash('Channel deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting channel: {e}', 'danger')
    return redirect(url_for('admin_panel'))

# --- Playlist Generator ---

@app.route('/iptvplaylist.m3u')
def generate_playlist():
    token_str = request.args.get('token')
    client_ip = request.remote_addr # Get the client's IP address
    user_agent = request.headers.get('User-Agent')
    referrer = request.headers.get('Referer')

    log_entry = AccessLog(
        ip_address=client_ip,
        token=token_str,
        user_agent=user_agent,
        referrer=referrer
    )
    db.session.add(log_entry)
    db.session.commit() # Commit immediately to ensure log is saved even if access is denied

    if not token_str:
        log_entry.status_code = 400
        db.session.commit()
        abort(400, description="Token parameter is missing.")

    token_obj = Token.query.filter_by(token=token_str).first()

    if not token_obj:
        log_entry.status_code = 404
        db.session.commit()
        abort(404, description="Invalid token.")

    if token_obj.is_banned:
        log_entry.status_code = 403
        db.session.commit()
        abort(403, description="Token is banned.")

    if token_obj.expiry < datetime.utcnow():
        log_entry.status_code = 403
        db.session.commit()
        abort(403, description="Token has expired.")

    # --- Device Limit Enforcement ---
    DEVICE_LIMIT = 4
    
    # Get all active IPs for this token (consider IPs recent access for "active" status)
    active_ips_for_token = ConnectedIP.query.filter(
        ConnectedIP.token_id == token_obj.id,
        ConnectedIP.last_access >= datetime.utcnow() - timedelta(hours=24) # Consider IPs active for the last 24 hours
    ).group_by(ConnectedIP.ip_address).all() # Group by IP to count unique IPs

    unique_ips_count = len(active_ips_for_token)
    
    # Check if the current IP is already among the active IPs
    current_ip_in_active_list = False
    for ip_entry in active_ips_for_token:
        if ip_entry.ip_address == client_ip:
            current_ip_in_active_list = True
            # Update last_access for this IP
            ip_entry.last_access = datetime.utcnow()
            break
    
    if not current_ip_in_active_list:
        if unique_ips_count >= DEVICE_LIMIT:
            log_entry.status_code = 403
            db.session.commit()
            abort(403, description=f"Device limit ({DEVICE_LIMIT}) exceeded for this token.")
        else:
            # Add the new IP
            new_connected_ip = ConnectedIP(token_id=token_obj.id, ip_address=client_ip, last_access=datetime.utcnow())
            db.session.add(new_connected_ip)
            
    db.session.commit() # Commit the IP updates/adds

    # --- Generate M3U Playlist ---
    playlist_content = "#EXTM3U\n"
    channels = Channel.query.all()
    for channel in channels:
        playlist_content += f'#EXTINF:-1 tvg-name="{channel.name}"'
        if channel.logo_url:
            playlist_content += f' tvg-logo="{channel.logo_url}"'
        playlist_content += f',{channel.name}\n'
        playlist_content += f'{channel.stream_url}\n'

    log_entry.status_code = 200
    db.session.commit()
    return Response(playlist_content, mimetype='application/x-mpegurl')

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Ensure tables are created when running directly
        # You can add initial admin user creation here if not using @app.before_first_request
    app.run(debug=True, host='0.0.0.0', port=5000)
