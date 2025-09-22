from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import json
import re

# Initialize Flask app
app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with reports
    reports = db.relationship('Report', backref='reporter', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Report model
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    image_filename = db.Column(db.String(200))
    is_urgent = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign key to User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Alert model
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    alert_type = db.Column(db.String(20), nullable=False)  # red, orange, yellow
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    radius = db.Column(db.Float, default=5.0)  # km radius
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Simple NLP classifier for urgency detection
def classify_urgency(text):
    """Basic keyword-based urgency classification"""
    urgent_keywords = [
        'emergency', 'urgent', 'help', 'fire', 'flood', 'earthquake',
        'tsunami', 'hurricane', 'tornado', 'explosion', 'accident',
        'injured', 'trapped', 'danger', 'immediate', 'critical'
    ]
    
    text_lower = text.lower()
    urgent_count = sum(1 for keyword in urgent_keywords if keyword in text_lower)
    
    # If 2 or more urgent keywords, classify as urgent
    return urgent_count >= 2

# Routes
@app.route('/')
def index():
    recent_alerts = Alert.query.filter_by(is_active=True).order_by(Alert.created_at.desc()).limit(5).all()
    return render_template('index.html', alerts=recent_alerts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful!')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).all()
    active_alerts = Alert.query.filter_by(is_active=True).order_by(Alert.created_at.desc()).all()
    return render_template('dashboard.html', reports=user_reports, alerts=active_alerts)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report_incident():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        
        # Convert coordinates to float if provided
        lat = float(latitude) if latitude else None
        lng = float(longitude) if longitude else None
        
        # Handle file upload
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add timestamp to prevent conflicts
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                image_filename = timestamp + filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        
        # Use NLP to classify urgency
        combined_text = f"{title} {description}"
        is_urgent = classify_urgency(combined_text)
        
        # Create report
        report = Report(
            title=title,
            description=description,
            latitude=lat,
            longitude=lng,
            image_filename=image_filename,
            is_urgent=is_urgent,
            user_id=current_user.id
        )
        
        db.session.add(report)
        db.session.commit()
        
        urgency_msg = "URGENT" if is_urgent else "normal"
        flash(f'Report submitted successfully! Classified as {urgency_msg} priority.')
        return redirect(url_for('dashboard'))
    
    return render_template('report_incident.html')

@app.route('/admin/create_alert', methods=['GET', 'POST'])
@login_required
def create_alert():
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            # Get form data
            title = request.form.get('title', '').strip()
            message = request.form.get('message', '').strip()
            alert_type = request.form.get('alert_type', '').strip()
            latitude = request.form.get('latitude', '').strip()
            longitude = request.form.get('longitude', '').strip()
            radius = request.form.get('radius', '5.0').strip()
            
            print(f"DEBUG: Received form data:")
            print(f"  Title: '{title}'")
            print(f"  Message: '{message}'")
            print(f"  Alert Type: '{alert_type}'")
            print(f"  Latitude: '{latitude}'")
            print(f"  Longitude: '{longitude}'")
            print(f"  Radius: '{radius}'")
            
            # Validate required fields
            if not title:
                flash('Alert title is required.')
                return render_template('create_alert.html')
            
            if not message:
                flash('Alert message is required.')
                return render_template('create_alert.html')
            
            if not alert_type or alert_type not in ['red', 'orange', 'yellow']:
                flash('Please select a valid alert level.')
                return render_template('create_alert.html')
            
            # Process coordinates - convert to float or set to None
            lat = None
            lng = None
            
            if latitude and latitude != '':
                try:
                    lat = float(latitude)
                    print(f"DEBUG: Converted latitude to: {lat}")
                except ValueError:
                    flash('Invalid latitude value. Please enter a valid number.')
                    return render_template('create_alert.html')
            
            if longitude and longitude != '':
                try:
                    lng = float(longitude)
                    print(f"DEBUG: Converted longitude to: {lng}")
                except ValueError:
                    flash('Invalid longitude value. Please enter a valid number.')
                    return render_template('create_alert.html')
            
            # Process radius
            try:
                radius_float = float(radius) if radius else 5.0
                if radius_float <= 0:
                    radius_float = 5.0
                print(f"DEBUG: Converted radius to: {radius_float}")
            except ValueError:
                radius_float = 5.0
                print(f"DEBUG: Invalid radius, using default: {radius_float}")
            
            # Create new alert object
            new_alert = Alert(
                title=title,
                message=message,
                alert_type=alert_type,
                latitude=lat,
                longitude=lng,
                radius=radius_float,
                created_by=current_user.id,
                is_active=True  # Make sure it's active by default
            )
            
            print(f"DEBUG: Created alert object:")
            print(f"  Title: {new_alert.title}")
            print(f"  Message: {new_alert.message}")
            print(f"  Type: {new_alert.alert_type}")
            print(f"  Coordinates: {new_alert.latitude}, {new_alert.longitude}")
            print(f"  Radius: {new_alert.radius}")
            print(f"  Created by: {new_alert.created_by}")
            
            # Save to database
            db.session.add(new_alert)
            db.session.commit()
            
            print(f"DEBUG: Alert saved to database with ID: {new_alert.id}")
            
            # Success message
            flash(f'✅ {alert_type.upper()} alert "{title}" created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            print(f"ERROR: Exception occurred while creating alert: {str(e)}")
            db.session.rollback()  # Rollback any database changes
            flash(f'Error creating alert: {str(e)}', 'error')
            return render_template('create_alert.html')
    
    # GET request - show the form
    return render_template('create_alert.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    # Get statistics
    total_reports = Report.query.count()
    urgent_reports = Report.query.filter_by(is_urgent=True).count()
    unverified_reports = Report.query.filter_by(is_verified=False).count()
    active_alerts = Alert.query.filter_by(is_active=True).count()
    
    # Get recent reports
    recent_reports = Report.query.order_by(Report.created_at.desc()).limit(10).all()
    
    # Get all reports with coordinates for map
    map_reports = Report.query.filter(Report.latitude.isnot(None), Report.longitude.isnot(None)).all()
    
    return render_template('admin_dashboard.html', 
                         total_reports=total_reports,
                         urgent_reports=urgent_reports,
                         unverified_reports=unverified_reports,
                         active_alerts=active_alerts,
                         recent_reports=recent_reports,
                         map_reports=map_reports)

@app.route('/admin/verify_report/<int:report_id>')
@login_required
def verify_report(report_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    report = Report.query.get_or_404(report_id)
    report.is_verified = not report.is_verified
    db.session.commit()
    
    status = "verified" if report.is_verified else "unverified"
    flash(f'Report "{report.title}" has been {status}')
    return redirect(url_for('admin_dashboard'))



# API ENDPOINT - Get all reports for map display (JSON format)
@app.route('/api/reports')
@login_required
def api_reports():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get all reports that have location data
    reports = Report.query.filter(Report.latitude.isnot(None), Report.longitude.isnot(None)).all()
    
    # Convert to JSON format for JavaScript
    report_data = []
    for report in reports:
        report_data.append({
            'id': report.id,
            'title': report.title,
            'description': report.description[:100] + '...' if len(report.description) > 100 else report.description,
            'latitude': report.latitude,
            'longitude': report.longitude,
            'is_urgent': report.is_urgent,
            'is_verified': report.is_verified,
            'created_at': report.created_at.strftime('%Y-%m-%d %H:%M'),
            'reporter': report.reporter.username
        })
    
    return jsonify(report_data)

# API ENDPOINT - Get all active alerts for map display (JSON format)
@app.route('/api/alerts')
def api_alerts():
    # Get all active alerts
    alerts = Alert.query.filter_by(is_active=True).all()
    
    # Convert to JSON format for JavaScript
    alert_data = []
    for alert in alerts:
        alert_data.append({
            'id': alert.id,
            'title': alert.title,
            'message': alert.message,
            'alert_type': alert.alert_type,
            'latitude': alert.latitude,
            'longitude': alert.longitude,
            'radius': alert.radius,
            'created_at': alert.created_at.strftime('%Y-%m-%d %H:%M')
        })
    
    return jsonify(alert_data)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@disaster.com',
                is_admin=True
            )
            admin.set_password('admin123')  # Change this in production!
            db.session.add(admin)
            db.session.commit()
            print("Admin user created! Username: admin, Password: admin123")
    
    app.run(debug=True)