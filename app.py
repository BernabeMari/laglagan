import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
from flask_socketio import SocketIO, emit
import urllib.parse
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')

# Admin credentials
ADMIN_USERNAME = 'zyber20'
ADMIN_PASSWORD = 'Bernabe202003!'

# MSSQL Connection
params = urllib.parse.quote_plus("Driver={ODBC Driver 17 for SQL Server};"
                                "Server=studenttracker.mssql.somee.com;"
                                "Database=studenttracker;"
                                "UID=zyber20_SQLLogin_1;"
                                "PWD=yqvmnkmzs8;"
                                "TrustServerCertificate=yes")

app.config['SQLALCHEMY_DATABASE_URI'] = f"mssql+pyodbc:///?odbc_connect={params}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize Socket.IO with CORS allowed
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# Connection event handlers for Socket.IO
@socketio.on('connect')
def handle_connect():
    print("Client connected:", request.sid)
    
@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected:", request.sid)

# Base User class for authentication
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(150), nullable=True)  # Added full_name field
    password_hash = db.Column(db.String(128), nullable=False)
    user_type = db.Column(db.String(10), nullable=False)  # 'student' or 'parent'
    
    __mapper_args__ = {
        'polymorphic_on': user_type,
        'polymorphic_identity': 'user'
    }
    
    def set_password(self, password):
        # Store plain password directly instead of hashing
        self.password_hash = password
        
    def check_password(self, password):
        # Direct comparison instead of hash checking
        return self.password_hash == password

# Parent model (needs to be defined before Student due to dependency)
class Parent(User):
    __tablename__ = 'parents'
    parent_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    phone_number = db.Column(db.String(20), nullable=True)
    
    # Instead of direct relationship to student, we'll use a back-reference
    
    __mapper_args__ = {
        'polymorphic_identity': 'parent',
    }

# Student model
class Student(User):
    __tablename__ = 'students'
    student_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    school = db.Column(db.String(100), nullable=True)
    grade_level = db.Column(db.String(20), nullable=True)
    
    # Relationship with parent - with explicit foreign key
    parent_id = db.Column(db.Integer, db.ForeignKey('parents.parent_id'), nullable=True)
    parent = db.relationship('Parent', foreign_keys=[parent_id], backref=db.backref('students', lazy=True))
    
    # Location updates
    location_updates = db.relationship('LocationUpdate', backref='student', lazy=True)
    
    __mapper_args__ = {
        'polymorphic_identity': 'student',
    }

class LocationUpdate(db.Model):
    __tablename__ = 'location_updates'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.student_id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class ConnectionRequest(db.Model):
    __tablename__ = 'connection_requests'
    id = db.Column(db.Integer, primary_key=True)
    from_parent_id = db.Column(db.Integer, db.ForeignKey('parents.parent_id'), nullable=True)
    from_student_id = db.Column(db.Integer, db.ForeignKey('students.student_id'), nullable=True)
    to_parent_id = db.Column(db.Integer, db.ForeignKey('parents.parent_id'), nullable=True)
    to_student_id = db.Column(db.Integer, db.ForeignKey('students.student_id'), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    from_parent = db.relationship('Parent', foreign_keys=[from_parent_id], backref='sent_requests_as_parent')
    from_student = db.relationship('Student', foreign_keys=[from_student_id], backref='sent_requests_as_student')
    to_parent = db.relationship('Parent', foreign_keys=[to_parent_id], backref='received_requests_as_parent')
    to_student = db.relationship('Student', foreign_keys=[to_student_id], backref='received_requests_as_student')
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions for getting complete objects
def get_student(current_user):
    """Get the student object from the current user"""
    if current_user.user_type != 'student':
        return None
    return Student.query.filter_by(user_id=current_user.id).first()

def get_parent(current_user):
    """Get the parent object from the current user"""
    if current_user.user_type != 'parent':
        return None
    return Parent.query.filter_by(user_id=current_user.id).first()

def get_student_for_parent(parent):
    """Get the student object for a parent"""
    if not parent:
        return None
    return Student.query.filter_by(parent_id=parent.parent_id).first()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        full_name = request.form.get('full_name')  # Get full_name from form
        password = request.form.get('password')
        user_type = request.form.get('user_type')
        
        # Check if user already exists
        user_exists = User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first()
        if user_exists:
            flash('Username or email already exists.')
            return redirect(url_for('signup'))
        
        # Create new user based on type
        if user_type == 'student':
            new_user = Student(username=username, email=email, full_name=full_name, user_type=user_type)
        else:
            new_user = Parent(username=username, email=email, full_name=full_name, user_type=user_type)
            
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            if user.user_type == 'student':
                return redirect(url_for('student_dashboard'))
            else:
                return redirect(url_for('parent_dashboard'))
        else:
            flash('Invalid username or password')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.user_type != 'student':
        flash('Access denied: You are not a student')
        return redirect(url_for('index'))
    
    # Get student object
    student = get_student(current_user)
    if not student:
        flash('Student account not found. Please contact support.')
        return redirect(url_for('index'))
    
    # Get pending connection requests
    pending_requests = ConnectionRequest.query.filter_by(
        to_student_id=student.student_id, 
        status='pending'
    ).all()
    
    return render_template('student_dashboard.html', 
                          pending_requests=pending_requests,
                          student=student)

@app.route('/parent/dashboard')
@login_required
def parent_dashboard():
    if current_user.user_type != 'parent':
        flash('Access denied: You are not a parent')
        return redirect(url_for('index'))
    
    # Get parent object
    parent = get_parent(current_user)
    if not parent:
        flash('Parent account not found. Please contact support.')
        return redirect(url_for('index'))
    
    # Get all students associated with this parent
    students = Student.query.filter_by(parent_id=parent.parent_id).all()
    
    # Get the first student for initial view, or None if no students
    student = students[0] if students else None
        
    return render_template('parent_dashboard.html',
                          parent=parent,
                          student=student)

@app.route('/connect', methods=['GET', 'POST'])
@login_required
def connect():
    # Students can't send connection requests, they can only view their connection status
    if current_user.user_type == 'student':
        student = get_student(current_user)
        return render_template('connect.html', student=student)
    
    # Get parent
    parent = get_parent(current_user)
    if not parent:
        flash('Parent account not found.')
        return redirect(url_for('index'))
    
    # Get sent requests
    sent_requests = ConnectionRequest.query.filter_by(
        from_parent_id=parent.parent_id,
        status='pending'
    ).all()
    
    if request.method == 'POST':
        email = request.form.get('email')
        target_user = User.query.filter_by(email=email).first()
        
        if not target_user:
            flash('Student with this email not found')
            return redirect(url_for('connect'))
            
        # Check if user is a student
        if target_user.user_type != 'student':
            flash('You can only connect with student accounts')
            return redirect(url_for('connect'))
        
        # Get student object
        student = Student.query.filter_by(user_id=target_user.id).first()
        
        # Check if already connected
        if student in parent.students:
            flash('You are already connected to this student')
            return redirect(url_for('connect'))
        
        # Check if connection request already exists
        existing_request = ConnectionRequest.query.filter_by(
            from_parent_id=parent.parent_id,
            to_student_id=student.student_id,
            status='pending'
        ).first()
        
        if existing_request:
            flash('A connection request has already been sent to this student')
            return redirect(url_for('connect'))
            
        # Create new connection request
        connection_request = ConnectionRequest(
            from_parent_id=parent.parent_id,
            to_student_id=student.student_id
        )
    
        db.session.add(connection_request)
        db.session.commit()
        
        flash('Connection request sent to the student')
        return redirect(url_for('connect'))
    
    return render_template('connect.html', parent=parent, sent_requests=sent_requests)

@app.route('/accept_request/<int:request_id>')
@login_required
def accept_request(request_id):
    # Only students can accept connection requests
    if current_user.user_type != 'student':
        flash('Only students can accept connection requests')
        return redirect(url_for('connect'))
    
    student = get_student(current_user)
    connection_request = ConnectionRequest.query.get_or_404(request_id)
    
    # Ensure the request is directed to the current student
    if connection_request.to_student_id != student.student_id:
        flash('Invalid request')
        return redirect(url_for('student_dashboard'))
        
    # Update the connection request status
    connection_request.status = 'accepted'
    
    # Establish the connection between student and parent
    student.parent_id = connection_request.from_parent_id
    
    db.session.commit()
    
    flash('Connection request accepted. You are now connected with the parent.')
    return redirect(url_for('student_dashboard'))

@app.route('/reject_request/<int:request_id>')
@login_required
def reject_request(request_id):
    # Only students can reject connection requests
    if current_user.user_type != 'student':
        flash('Only students can reject connection requests')
        return redirect(url_for('connect'))
    
    student = get_student(current_user)
    connection_request = ConnectionRequest.query.get_or_404(request_id)
    
    # Ensure the request is directed to the current student
    if connection_request.to_student_id != student.student_id:
        flash('Invalid request')
        return redirect(url_for('student_dashboard'))
    
    # Update the connection request status
    connection_request.status = 'rejected'
    db.session.commit()
    
    flash('Connection request rejected')
    return redirect(url_for('student_dashboard'))

# API routes for location tracking
@app.route('/api/start_tracking', methods=['POST'])
@login_required
def start_tracking():
    if current_user.user_type != 'student':
        return jsonify({'error': 'Only students can start tracking'}), 403
    
    student = get_student(current_user)    
    if not student:
        return jsonify({'error': 'Student account not found'}), 404
    
    # Deactivate all previous active sessions
    active_sessions = LocationUpdate.query.filter_by(student_id=student.student_id, is_active=True).all()
    for session in active_sessions:
        session.is_active = False
        
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': 'Tracking started'})

@app.route('/api/update_location', methods=['POST'])
@login_required
def update_location():
    if current_user.user_type != 'student':
        return jsonify({'error': 'Only students can update location'}), 403
        
    student = get_student(current_user)
    if not student:
        return jsonify({'error': 'Student account not found'}), 404
    
    data = request.get_json()
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    
    if not latitude or not longitude:
        return jsonify({'error': 'Latitude and longitude are required'}), 400
        
    # Create new location update
    location_update = LocationUpdate(
        student_id=student.student_id,
        latitude=latitude,
        longitude=longitude,
        is_active=True
    )
    
    db.session.add(location_update)
    db.session.commit()
    
    # Emit to the connected parent
    if student.parent:
        print(f"DEBUG: Emitting location update for student {student.username} (ID: {student.student_id}) to parent {student.parent.username} (ID: {student.parent.user_id})")
        
        event_name = f'location_update_{student.parent.user_id}'
        data_to_emit = {
            'latitude': latitude,
            'longitude': longitude,
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'student_username': student.username,
            'student_full_name': student.full_name,
            'student_id': student.student_id
        }
        
        print(f"DEBUG: Event name: {event_name}")
        print(f"DEBUG: Data to emit: {data_to_emit}")
        
        socketio.emit(event_name, data_to_emit)
    else:
        print(f"DEBUG: Student {student.username} has no connected parent, not emitting update")
    
    return jsonify({'status': 'success'})

@app.route('/api/stop_tracking', methods=['POST'])
@login_required
def stop_tracking():
    if current_user.user_type != 'student':
        return jsonify({'error': 'Only students can stop tracking'}), 403
        
    student = get_student(current_user)
    if not student:
        return jsonify({'error': 'Student account not found'}), 404
        
    # Deactivate all active sessions
    active_sessions = LocationUpdate.query.filter_by(student_id=student.student_id, is_active=True).all()
    for session in active_sessions:
        session.is_active = False
        
    db.session.commit()
    
    # Notify the parent that tracking has stopped
    if student.parent:
        print(f"DEBUG: Emitting tracking stopped for student {student.username} (ID: {student.student_id}) to parent {student.parent.username} (ID: {student.parent.user_id})")
        
        event_name = f'tracking_stopped_{student.parent.user_id}'
        data_to_emit = {
            'message': 'Student has stopped tracking',
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'student_username': student.username,
            'student_full_name': student.full_name,
            'student_id': student.student_id
        }
        
        print(f"DEBUG: Event name: {event_name}")
        print(f"DEBUG: Data to emit: {data_to_emit}")
        
        socketio.emit(event_name, data_to_emit)
    else:
        print(f"DEBUG: Student {student.username} has no connected parent, not emitting tracking stopped")
    
    return jsonify({'status': 'success', 'message': 'Tracking stopped'})

@app.route('/api/get_student_location/<int:student_id>')
@login_required
def get_student_location(student_id):
    if current_user.user_type != 'parent':
        return jsonify({'error': 'Only parents can view student locations'}), 403
        
    parent = get_parent(current_user)
    if not parent:
        return jsonify({'error': 'Parent account not found'}), 404
        
    # Check if the student is associated with this parent
    student = Student.query.filter_by(student_id=student_id, parent_id=parent.parent_id).first()
    if not student:
        print(f"DEBUG: Parent {parent.username} (ID: {parent.parent_id}) attempted to get location for student ID {student_id} but they are not connected")
        return jsonify({'error': 'No student found with this ID or not connected to you'}), 404
        
    # Get the most recent active location update for the student
    location = LocationUpdate.query.filter_by(
        student_id=student.student_id,
        is_active=True
    ).order_by(LocationUpdate.timestamp.desc()).first()
    
    if not location:
        print(f"DEBUG: No active location found for student {student.username} (ID: {student.student_id})")
        return jsonify({'error': 'No active location tracking for student'}), 404
    
    print(f"DEBUG: Returning location for student {student.username} (ID: {student.student_id}) to parent {parent.username}")
    return jsonify({
        'latitude': location.latitude,
        'longitude': location.longitude,
        'timestamp': location.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'student_name': student.username,
        'student_full_name': student.full_name,
        'student_id': student.student_id
    })

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            # Set admin session
            session['admin_logged_in'] = True
            return redirect(url_for('admin_users'))
        else:
            flash('Invalid admin credentials')
            
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    # Clear admin session
    session.pop('admin_logged_in', None)
    flash('Admin logged out successfully')
    return redirect(url_for('admin_login'))

# Admin middleware - function to check if admin is logged in
def admin_required(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return view_func(*args, **kwargs)
    return decorated_view

@app.route('/admin/users')
@admin_required
def admin_users():
    # Get all users
    all_users = User.query.all()
    
    # Prepare user data for display
    users_data = []
    for user in all_users:
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name,
            'password': user.password_hash,
            'user_type': user.user_type
        }
        users_data.append(user_data)
    
    return render_template('admin_users.html', users=users_data, ADMIN_USERNAME=ADMIN_USERNAME)

# Admin routes
@app.route('/admin')
def admin_index():
    # Redirect to admin users page if logged in, otherwise to login page
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_users'))
    else:
        return redirect(url_for('admin_login'))

# Initialize the database
@app.cli.command('init-db')
def init_db_command():
    db.create_all()
    print('Initialized the database.')

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True) 