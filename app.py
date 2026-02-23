from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import uuid
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'atoz-decorators-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///decorators.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# -------------------- MODELS --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    bookings = db.relationship('Booking', backref='user', lazy=True, cascade='all, delete-orphan')

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.String(50), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    event_date = db.Column(db.String(20), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    # guests column removed
    venue_address = db.Column(db.Text, nullable=False)
    special_requests = db.Column(db.Text)
    payment_method = db.Column(db.String(50), nullable=False)
    services = db.Column(db.Text, nullable=False)  # JSON
    total_amount = db.Column(db.Float, nullable=False)
    booking_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='confirmed')

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50))
    image_url = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20))
    subject = db.Column(db.String(100))
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

# -------------------- ADMIN REQUIRED DECORATOR --------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first!', 'error')
            return redirect(url_for('admin_login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# -------------------- DATABASE INITIALIZATION --------------------
def init_database():
    with app.app_context():
        print("⚙️ Initializing database...", flush=True)
        db.create_all()
        print("✅ Database tables ready.", flush=True)
        
        # Create default admin
        if not User.query.filter_by(email='admin@atozdecorators.com').first():
            admin = User(
                username='admin',
                email='admin@atozdecorators.com',
                phone='1234567890',
                password=generate_password_hash('admin123', method='pbkdf2:sha256'),
                is_admin=True
            )
            db.session.add(admin)
            print("✅ Admin created.", flush=True)
        
        # Create default guest user (for non-login bookings)
        if not User.query.filter_by(username='guest').first():
            guest = User(
                username='guest',
                email='guest@atozdecorators.com',
                phone='0000000000',
                password=generate_password_hash('guest123', method='pbkdf2:sha256'),
                is_admin=False
            )
            db.session.add(guest)
            print("✅ Guest user created.", flush=True)
        
        # Add sample services (9 packages)
        if not Service.query.first():
            services = [
                Service(name='Wedding Decorations', price=50000, category='wedding', 
                        description='Complete wedding decoration including mandap, stage, floral arrangements & lighting.',
                        image_url='https://images.unsplash.com/photo-1511285560929-80b456fea0bc'),
                Service(name='Birthday Parties', price=15000, category='birthday',
                        description='Theme-based birthday decorations with balloons, props, photo booth & return gifts.',
                        image_url='https://images.unsplash.com/photo-1530103862676-de8c9debad1d'),
                Service(name='Corporate Events', price=30000, category='corporate',
                        description='Professional setups for conferences, product launches, branding & AV solutions.',
                        image_url='https://images.unsplash.com/photo-1492684223066-e9e4aab4d25e'),
                Service(name='Anniversary Decor', price=20000, category='anniversary',
                        description='Elegant anniversary decorations with romantic themes, candle lights & personalized touches.',
                        image_url='https://images.unsplash.com/photo-1519225421980-715cb0215aed'),
                Service(name='Baby Shower', price=12000, category='baby-shower',
                        description='Cute and colorful baby shower decorations with themes, balloon arch & games setup.',
                        image_url='https://images.unsplash.com/photo-1532413992378-f169ac26fff0'),
                Service(name='Festival Decor', price=10000, category='festival',
                        description='Traditional festival decorations for Diwali, Christmas, Holi, Ganesh Chaturthi & more.',
                        image_url='https://images.unsplash.com/photo-1603899122634-f086ca5f5ddd'),
                Service(name='Car Decoration', price=8000, category='car',
                        description='Luxury car decoration for weddings, gift cars, VIP events with flowers & ribbons.',
                        image_url='https://images.unsplash.com/photo-1549399542-7e3f8b79c341'),
                Service(name='Murti Decoration', price=7000, category='murti',
                        description='Traditional idol decoration for Ganesh Chaturthi, Navratri, Durga Puja with flowers & lights.',
                        image_url='https://images.pexels.com/photos/16213627/pexels-photo-16213627.jpeg'),
                Service(name='Opening Ceremony', price=9000, category='inauguration',
                        description='Grand inauguration decoration for shops, offices, showrooms with floral setup & ribbon cutting.',
                        image_url='https://images.pexels.com/photos/5669602/pexels-photo-5669602.jpeg'),
            ]
            for s in services:
                db.session.add(s)
            print("✅ 9 sample services added.", flush=True)
        
        try:
            db.session.commit()
            print("✅ Database committed successfully.", flush=True)
        except Exception as e:
            db.session.rollback()
            print(f"❌ Database init error: {e}", flush=True)

init_database()

# -------------------- PAGE ROUTES (for all your HTML files) --------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    services = Service.query.filter_by(is_active=True).all()
    return render_template('home.html', services=services)

@app.route('/wedding')
def wedding_page():
    return render_template('wedding.html')

@app.route('/birthday')
def birthday_page():
    return render_template('birthday.html')

@app.route('/car')
def car_page():
    return render_template('car.html')

@app.route('/festival')
def festival_page():
    return render_template('festival.html')

@app.route('/newopening')
def newopening_page():
    return render_template('newopening.html')

@app.route('/murti')
def murti_page():
    return render_template('murti.html')

@app.route('/corporate')
def corporate_page():
    return render_template('corporate.html')

@app.route('/house')
def house_page():
    return render_template('house.html')



# -------------------- USER AUTH ROUTES --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_email'] = user.email
            session['user_phone'] = user.phone
            session['is_admin'] = user.is_admin
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        if password != confirm:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
        hashed = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, phone=phone, password=hashed)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            print(f"Registration error: {e}", flush=True)
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

# -------------------- API ROUTES (AJAX) --------------------
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email_or_username = data.get('email')
    password = data.get('password')
    user = User.query.filter((User.username == email_or_username) | (User.email == email_or_username)).first()
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['username'] = user.username
        session['user_email'] = user.email
        session['user_phone'] = user.phone
        session['is_admin'] = user.is_admin
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Invalid credentials'})

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')
    if not username or not email or not phone or not password:
        return jsonify({'success': False, 'message': 'All fields required'})
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already exists'})
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already registered'})
    hashed = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, email=email, phone=phone, password=hashed)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"API Register error: {e}", flush=True)
        return jsonify({'success': False, 'message': 'Registration failed'})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/check_login')
def api_check_login():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return jsonify({'logged_in': True, 'username': user.username, 'is_admin': user.is_admin})
    return jsonify({'logged_in': False})

@app.route('/api/get_user_info')
def api_get_user_info():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return jsonify({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'phone': user.phone,
                'is_admin': user.is_admin
            })
    return jsonify({'error': 'Not logged in'})

@app.route('/api/create_booking', methods=['POST'])
def api_create_booking():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data received'}), 400
        booking_id = 'ADZ-' + str(uuid.uuid4())[:8].upper()
        guest = User.query.filter_by(username='guest').first()
        if not guest:
            guest = User(username='guest', email='guest@atozdecorators.com', phone='0000000000',
                        password=generate_password_hash('guest123', method='pbkdf2:sha256'), is_admin=False)
            db.session.add(guest)
            db.session.commit()
        user_id = session['user_id'] if 'user_id' in session else guest.id
        required = ['full_name', 'email', 'phone', 'event_date', 'event_type', 'payment_method', 'services', 'total_amount']
        for field in required:
            if field not in data:
                return jsonify({'success': False, 'message': f'Missing field: {field}'}), 400
        booking = Booking(
            booking_id=booking_id,
            user_id=user_id,
            full_name=data['full_name'],
            email=data['email'],
            phone=data['phone'],
            event_date=data['event_date'],
            event_type=data['event_type'],
            # guests field removed
            venue_address=data.get('venue_address', 'A to Z Decorators'),
            special_requests=data.get('special_requests', ''),
            payment_method=data['payment_method'],
            services=json.dumps(data['services']),
            total_amount=float(data['total_amount']),
            status='confirmed'
        )
        db.session.add(booking)
        db.session.commit()
        print(f"✅ Booking saved: {booking_id}", flush=True)
        return jsonify({
            'success': True,
            'booking_id': booking_id,
            'booking_date': booking.booking_date.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        db.session.rollback()
        print(f"❌ Booking error: {e}", flush=True)
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/my_bookings')
def api_my_bookings():
    if 'user_id' not in session:
        return jsonify({'error': 'Please login first!'})
    bookings = Booking.query.filter_by(user_id=session['user_id']).order_by(Booking.booking_date.desc()).all()
    booking_list = []
    for b in bookings:
        try:
            services = json.loads(b.services) if b.services else []
        except:
            services = []
        booking_list.append({
            'booking_id': b.booking_id,
            'event_date': b.event_date,
            'event_type': b.event_type,
            'total_amount': b.total_amount,
            'status': b.status,
            'services': services
        })
    return jsonify({'success': True, 'bookings': booking_list})

@app.route('/api/contact', methods=['POST'])
def api_contact():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data received'}), 400
        name = data.get('name')
        email = data.get('email')
        phone = data.get('phone', '')
        subject = data.get('subject', '')
        message = data.get('message')
        if not name or not email or not message:
            return jsonify({'success': False, 'message': 'Name, Email and Message are required!'}), 400
        contact = Contact(name=name, email=email, phone=phone, subject=subject, message=message)
        db.session.add(contact)
        db.session.commit()
        print(f"✅ Contact saved from {email}", flush=True)
        return jsonify({'success': True, 'message': 'Your message has been sent successfully!'})
    except Exception as e:
        db.session.rollback()
        print(f"❌ Contact error: {e}", flush=True)
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------- ADMIN PANEL ROUTES --------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """अ‍ॅडमिन लॉगिन - adminlogin.html वापरतो"""
    if session.get('user_id'):
        user = User.query.get(session['user_id'])
        if user and user.is_admin:
            return redirect(url_for('admin_panel'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password) and user.is_admin:
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_email'] = user.email
            session['user_phone'] = user.phone
            session['is_admin'] = user.is_admin
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid credentials or not an admin!', 'error')
            return redirect(url_for('admin_login'))
    return render_template('adminlogin.html')

@app.route('/admin/panel')
@admin_required
def admin_panel():
    """अ‍ॅडमिन डॅशबोर्ड - admin.html रेंडर करतो"""
    total_users = User.query.count()
    total_bookings = Booking.query.count()
    total_services = Service.query.count()
    total_contacts = Contact.query.count()
    recent_bookings = Booking.query.order_by(Booking.booking_date.desc()).limit(5).all()
    all_bookings = Booking.query.order_by(Booking.booking_date.desc()).all()
    all_users = User.query.order_by(User.created_at.desc()).all()
    all_services = Service.query.all()
    all_contacts = Contact.query.order_by(Contact.created_at.desc()).all()
    return render_template('admin.html',
                           total_users=total_users,
                           total_bookings=total_bookings,
                           total_services=total_services,
                           total_contacts=total_contacts,
                           recent_bookings=recent_bookings,
                           all_bookings=all_bookings,
                           all_users=all_users,
                           all_services=all_services,
                           all_contacts=all_contacts)

@app.route('/admin/booking/update/<int:id>', methods=['POST'])
@admin_required
def admin_update_booking(id):
    booking = Booking.query.get_or_404(id)
    booking.status = request.form.get('status', booking.status)
    db.session.commit()
    flash(f'Booking {booking.booking_id} status updated to {booking.status}!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/toggle-admin/<int:id>')
@admin_required
def admin_toggle_user_admin(id):
    if id == session['user_id']:
        flash('You cannot change your own admin status!', 'error')
        return redirect(url_for('admin_panel'))
    user = User.query.get_or_404(id)
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f'Admin status for {user.username} updated!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/service/toggle/<int:id>')
@admin_required
def admin_toggle_service(id):
    service = Service.query.get_or_404(id)
    service.is_active = not service.is_active
    db.session.commit()
    flash(f'Service "{service.name}" is now {"Active" if service.is_active else "Inactive"}!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/service/add', methods=['POST'])
@admin_required
def admin_add_service():
    name = request.form.get('name')
    price = float(request.form.get('price'))
    category = request.form.get('category')
    description = request.form.get('description', '')
    image_url = request.form.get('image_url', '')
    new_service = Service(
        name=name,
        price=price,
        category=category,
        description=description,
        image_url=image_url,
        is_active=True
    )
    db.session.add(new_service)
    db.session.commit()
    flash(f'Service "{name}" added successfully!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/service/delete/<int:id>')
@admin_required
def admin_delete_service(id):
    service = Service.query.get_or_404(id)
    name = service.name
    db.session.delete(service)
    db.session.commit()
    flash(f'Service "{name}" deleted!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/contact/mark-read/<int:id>')
@admin_required
def admin_contact_mark_read(id):
    contact = Contact.query.get_or_404(id)
    contact.is_read = True
    db.session.commit()
    flash('Contact marked as read!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/contact/delete/<int:id>')
@admin_required
def admin_contact_delete(id):
    contact = Contact.query.get_or_404(id)
    db.session.delete(contact)
    db.session.commit()
    flash('Contact deleted!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/reset_db')
@admin_required
def reset_db():
    try:
        db.drop_all()
        db.create_all()
        print("✅ Database dropped and recreated.", flush=True)
        admin = User(
            username='admin',
            email='admin@atozdecorators.com',
            phone='1234567890',
            password=generate_password_hash('admin123', method='pbkdf2:sha256'),
            is_admin=True
        )
        db.session.add(admin)
        guest = User(
            username='guest',
            email='guest@atozdecorators.com',
            phone='0000000000',
            password=generate_password_hash('guest123', method='pbkdf2:sha256'),
            is_admin=False
        )
        db.session.add(guest)
        services = [
            Service(name='Wedding Decorations', price=50000, category='wedding', 
                    description='Complete wedding decoration...', image_url='https://images.unsplash.com/photo-1511285560929-80b456fea0bc'),
            Service(name='Birthday Parties', price=15000, category='birthday',
                    description='Theme-based birthday decorations...', image_url='https://images.unsplash.com/photo-1530103862676-de8c9debad1d'),
            Service(name='Corporate Events', price=30000, category='corporate',
                    description='Professional setups for conferences...', image_url='https://images.unsplash.com/photo-1492684223066-e9e4aab4d25e'),
            Service(name='Anniversary Decor', price=20000, category='anniversary',
                    description='Elegant anniversary decorations...', image_url='https://images.unsplash.com/photo-1519225421980-715cb0215aed'),
            Service(name='Baby Shower', price=12000, category='baby-shower',
                    description='Cute and colorful baby shower decorations...', image_url='https://images.unsplash.com/photo-1532413992378-f169ac26fff0'),
            Service(name='Festival Decor', price=10000, category='festival',
                    description='Traditional festival decorations...', image_url='https://images.unsplash.com/photo-1603899122634-f086ca5f5ddd'),
            Service(name='Car Decoration', price=8000, category='car',
                    description='Luxury car decoration for weddings...', image_url='https://images.unsplash.com/photo-1549399542-7e3f8b79c341'),
            Service(name='Murti Decoration', price=7000, category='murti',
                    description='Traditional idol decoration for festivals...', image_url='https://images.pexels.com/photos/16213627/pexels-photo-16213627.jpeg'),
            Service(name='Opening Ceremony', price=9000, category='inauguration',
                    description='Grand inauguration decoration for shops & offices...', image_url='https://images.pexels.com/photos/5669602/pexels-photo-5669602.jpeg'),
        ]
        for s in services:
            db.session.add(s)
        db.session.commit()
        flash('Database reset! Admin, Guest and 9 services recreated.', 'success')
        print("✅ Database reset completed.", flush=True)
    except Exception as e:
        db.session.rollback()
        flash(f'Reset failed: {e}', 'error')
        print(f"❌ Reset error: {e}", flush=True)
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000, use_reloader=False)