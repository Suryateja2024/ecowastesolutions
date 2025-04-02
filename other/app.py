from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import requests
import json
from datetime import datetime
import random
import razorpay
from other.models import db, User, Scrap, ProcessedScrap, CostPerKg, Purchase
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user, login_user, LoginManager, logout_user
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default-secret-key')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Razorpay Configuration
RAZORPAY_KEY_ID = os.getenv('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET')
client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Configuration
database_url = os.getenv('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    # Convert postgres:// to postgresql:// for SQLAlchemy
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///scrap.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Add these configurations after app initialization
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize database
db.init_app(app)

# Cashfree Payment Gateway Configuration
CASHFREE_APP_ID = os.getenv('CASHFREE_APP_ID')
CASHFREE_SECRET_KEY = os.getenv('CASHFREE_SECRET_KEY')
CASHFREE_API_URL = os.getenv('CASHFREE_API_URL', 'https://sandbox.cashfree.com/pg/orders')

def init_db():
    with app.app_context():
        try:
            # Create all tables if they don't exist
            db.create_all()
            logger.info("Database tables created successfully!")
            
            # Create default users if they don't exist
            if not User.query.filter_by(username='admin').first():
                admin = User(
                    username='admin',
                    password=generate_password_hash('admin123'),
                    role='admin'
                )
                db.session.add(admin)
                logger.info("Created default admin user")
                
            if not User.query.filter_by(username='processor').first():
                processor = User(
                    username='processor',
                    password=generate_password_hash('processor123'),
                    role='processor'
                )
                db.session.add(processor)
                logger.info("Created default processor user")
                
            if not User.query.filter_by(username='buyer').first():
                buyer = User(
                    username='buyer',
                    password=generate_password_hash('buyer123'),
                    role='buyer'
                )
                db.session.add(buyer)
                logger.info("Created default buyer user")
            
            # Create default cost settings if they don't exist
            if not CostPerKg.query.first():
                cost_settings = CostPerKg(
                    steel_cost=12,
                    aluminium_cost=10,
                    copper_cost=8
                )
                db.session.add(cost_settings)
                logger.info("Created default cost settings")
                
            db.session.commit()
            logger.info("Database initialization completed successfully!")
        except Exception as e:
            logger.error(f"Error during database initialization: {str(e)}")
            db.session.rollback()

# Initialize the database when the application starts
init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            logger.info(f"Login attempt for user: {username}")
            
            if not username or not password:
                flash('Username and password are required.', 'error')
                logger.warning(f"Login failed: Missing username or password")
                return render_template('login.html')
            
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                login_user(user)
                flash('Login successful!', 'success')
                logger.info(f"User {username} logged in successfully")
                
                if user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user.role == 'processor':
                    return redirect(url_for('processor_dashboard'))
                elif user.role == 'buyer':
                    return redirect(url_for('buyer_dashboard'))
                elif user.role == 'recycler':
                    return redirect(url_for('recycler_dashboard'))
                else:
                    return redirect(url_for('user_dashboard'))
            else:
                flash('Invalid username or password.', 'error')
                logger.warning(f"Login failed: Invalid credentials for user {username}")
        except Exception as e:
            logger.error(f"Error during login: {str(e)}")
            flash('An error occurred during login. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role')
            
            # Validate input
            if not username or not password or not role:
                return render_template("register.html", error="All fields are required!")
            
            # Only allow user and recycler roles
            if role not in ['user', 'recycler']:
                return render_template("register.html", error="Invalid role! Only users and recyclers can register.")
            
            # Check if username already exists
            if User.query.filter_by(username=username).first():
                return render_template("register.html", error="Username already exists!")
                
            # Create new user
            hashed_password = generate_password_hash(password)
            new_user = User(
                username=username,
                password=hashed_password,
                role=role
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Registration error: {str(e)}")
            return render_template("register.html", error=f"An error occurred during registration: {str(e)}")
            
    return render_template("register.html")

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        flash('Access denied. User privileges required.', 'error')
        return redirect(url_for('login'))
    
    # Get all scraps for the current user, ordered by status and date
    user_scraps = Scrap.query.filter_by(user_id=current_user.id).order_by(
        Scrap.status.desc(),
        Scrap.created_at.desc()
    ).all()
    
    return render_template("user_dashboard.html", scrap_data=user_scraps)

@app.route('/submit_scrap', methods=['POST'])
@login_required
def submit_scrap():
    try:
        name = request.form['name']
        condition = request.form['condition']
        weight = float(request.form['weight'])
        price = float(request.form['price'])
        pickup_date = datetime.strptime(request.form['pickup_date'], '%Y-%m-%d').date()
        pickup_slot = request.form['pickup_slot']
        address = request.form['address']
        
        # Check if a similar scrap entry already exists
        existing_scrap = Scrap.query.filter_by(
            name=name,
            condition=condition,
            weight=weight,
            price=price,
            pickup_date=pickup_date,
            pickup_slot=pickup_slot,
            user_id=current_user.id,
            status='pending'
        ).first()
        
        if existing_scrap:
            flash('A similar scrap entry is already pending approval.', 'warning')
            return redirect(url_for('user_dashboard'))
        
        # Handle image upload
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = os.path.join('uploads', filename)
        
        new_scrap = Scrap(
            name=name,
            condition=condition,
            weight=weight,
            price=price,
            pickup_date=pickup_date,
            pickup_slot=pickup_slot,
            address=address,
            image_path=image_path,
            user_id=current_user.id,
            status='pending'
        )
        
        db.session.add(new_scrap)
        db.session.commit()
        flash('Scrap submitted successfully!', 'success')
        return redirect(url_for('user_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error submitting scrap: {str(e)}', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/processor_dashboard', methods=['GET', 'POST'])
@login_required
def processor_dashboard():
    if current_user.role != 'processor':
        flash('Access denied. Processor privileges required.', 'error')
        return redirect(url_for('login'))
    
    approved_scraps = Scrap.query.filter_by(status="approved").all()
    processed_scrap = ProcessedScrap.query.filter_by(buyer_id=None).first()
    
    if request.method == 'POST':
        try:
            steel = float(request.form.get('steel', 0))
            aluminium = float(request.form.get('aluminium', 0))
            copper = float(request.form.get('copper', 0))
            
            if not processed_scrap:
                processed_scrap = ProcessedScrap()
                db.session.add(processed_scrap)
            
            # Accumulate the quantities instead of replacing
            processed_scrap.steel = (processed_scrap.steel or 0) + steel
            processed_scrap.aluminium = (processed_scrap.aluminium or 0) + aluminium
            processed_scrap.copper = (processed_scrap.copper or 0) + copper
            
            db.session.commit()
            flash('Scrap quantities updated successfully!', 'success')
            
            # Refresh the processed scrap data
            processed_scrap = ProcessedScrap.query.filter_by(buyer_id=None).first()
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating scrap quantities: {str(e)}', 'error')
        
    return render_template("processor_dashboard.html", scraps=approved_scraps, processed_scrap=processed_scrap)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    # Get all scraps with their status
    pending_scraps = Scrap.query.filter_by(status='pending').all()
    approved_scraps = Scrap.query.filter_by(status='approved').all()
    rejected_scraps = Scrap.query.filter_by(status='rejected').all()
    
    # Calculate total scraps and weights
    total_scraps = len(pending_scraps) + len(approved_scraps) + len(rejected_scraps)
    total_weight = sum(scrap.weight for scrap in pending_scraps) + \
                  sum(scrap.weight for scrap in approved_scraps) + \
                  sum(scrap.weight for scrap in rejected_scraps)
    
    # Get cost settings
    cost_settings = CostPerKg.query.first()
    
    # Calculate total value
    total_value = sum(scrap.weight * getattr(cost_settings, f"{scrap.condition.lower()}_cost", 0) 
                     for scrap in pending_scraps + approved_scraps + rejected_scraps)
    
    # Get processed scrap statistics
    processed_scraps = ProcessedScrap.query.all()
    total_processed_steel = sum(scrap.steel for scrap in processed_scraps)
    total_processed_aluminium = sum(scrap.aluminium for scrap in processed_scraps)
    total_processed_copper = sum(scrap.copper for scrap in processed_scraps)
    
    # Get available processed scrap (not purchased)
    available_scrap = ProcessedScrap.query.filter_by(buyer_id=None).first()
    
    # Get revenue statistics
    purchases = Purchase.query.filter_by(payment_status='completed').all()
    total_revenue = sum(purchase.price for purchase in purchases)
    total_purchases = len(purchases)
    
    # Get recent purchases with buyer information
    recent_purchases = Purchase.query.filter_by(payment_status='completed').order_by(Purchase.created_at.desc()).limit(10).all()
    
    # Get user statistics
    total_users = User.query.filter_by(role='user').count()
    total_recyclers = User.query.filter_by(role='recycler').count()
    total_processors = User.query.filter_by(role='processor').count()
    total_buyers = User.query.filter_by(role='buyer').count()
    
    return render_template('admin_dashboard.html',
                         pending_scraps=pending_scraps,
                         approved_scraps=approved_scraps,
                         rejected_scraps=rejected_scraps,
                         cost_settings=cost_settings,
                         total_scraps=total_scraps,
                         total_weight=total_weight,
                         total_value=total_value,
                         total_processed_steel=total_processed_steel,
                         total_processed_aluminium=total_processed_aluminium,
                         total_processed_copper=total_processed_copper,
                         total_users=total_users,
                         total_recyclers=total_recyclers,
                         total_processors=total_processors,
                         total_buyers=total_buyers,
                         available_scrap=available_scrap,
                         total_revenue=total_revenue,
                         total_purchases=total_purchases,
                         recent_purchases=recent_purchases)

@app.route('/admin/approve_scrap/<int:scrap_id>', methods=['POST'])
@login_required
def approve_scrap(scrap_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    try:
        scrap = Scrap.query.get_or_404(scrap_id)
        if scrap.status != 'pending':
            flash('This scrap has already been processed.', 'warning')
            return redirect(url_for('admin_dashboard'))
            
        scrap.status = 'approved'
        db.session.commit()
        flash('Scrap approved successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error approving scrap: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_scrap/<int:scrap_id>', methods=['POST'])
@login_required
def reject_scrap(scrap_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    try:
        scrap = Scrap.query.get_or_404(scrap_id)
        if scrap.status != 'pending':
            flash('This scrap has already been processed.', 'warning')
            return redirect(url_for('admin_dashboard'))
            
        scrap.status = 'rejected'
        db.session.commit()
        flash('Scrap rejected successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error rejecting scrap: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/buyer/dashboard', methods=['GET', 'POST'])
@login_required
def buyer_dashboard():
    if current_user.role != 'buyer':
        flash('Access denied. Buyer privileges required.', 'error')
        return redirect(url_for('login'))
    
    # Get processed scrap data from processor
    processed_scrap = ProcessedScrap.query.filter_by(buyer_id=None).first()  # Get processor's processed scrap
    
    if request.method == 'POST':
        try:
            steel = float(request.form.get('steel', 0))
            aluminium = float(request.form.get('aluminium', 0))
            copper = float(request.form.get('copper', 0))
            
            if not processed_scrap:
                flash('No processed scrap available for purchase!', 'error')
                return redirect(url_for('buyer_dashboard'))
            
            # Check if requested quantities are available
            if (steel > (processed_scrap.steel or 0) or 
                aluminium > (processed_scrap.aluminium or 0) or 
                copper > (processed_scrap.copper or 0)):
                flash('Requested quantities are not available!', 'error')
                return redirect(url_for('buyer_dashboard'))
            
            # Add to cart
            if 'cart' not in session:
                session['cart'] = []
            
            if steel > 0:
                session['cart'].append({
                    'type': 'steel',
                    'weight': steel,
                    'price': steel * CostPerKg.query.first().steel_cost
                })
            
            if aluminium > 0:
                session['cart'].append({
                    'type': 'aluminium',
                    'weight': aluminium,
                    'price': aluminium * CostPerKg.query.first().aluminium_cost
                })
            
            if copper > 0:
                session['cart'].append({
                    'type': 'copper',
                    'weight': copper,
                    'price': copper * CostPerKg.query.first().copper_cost
                })
            
            session['grand_total'] = sum(item['price'] for item in session['cart'])
            flash('Items added to cart successfully!', 'success')
            
        except Exception as e:
            flash(f'Error adding items to cart: {str(e)}', 'error')
    
    # Get cost settings
    cost_settings = CostPerKg.query.first()
    
    return render_template('buyer_dashboard.html', 
                         processed_scrap=processed_scrap,
                         cost_settings=cost_settings)

@app.route('/buy_now', methods=['POST'])
@login_required
def buy_now():
    if current_user.role != 'buyer':
        flash('Access denied. Buyer privileges required.', 'error')
        return redirect(url_for('login'))
    
    scrap_type = request.form.get('scrap_type')
    weight = float(request.form.get('weight'))
    cost_per_kg = CostPerKg.query.first()

    if not scrap_type or not weight:
        return "Invalid data!", 400

    processed_scrap = ProcessedScrap.query.first()
    if processed_scrap and getattr(processed_scrap, scrap_type) >= weight:
        price = weight * getattr(cost_per_kg, f"{scrap_type}_cost")

        if 'cart' not in session:
            session['cart'] = []
        
        session['cart'].append({
            'scrap_type': scrap_type, 
            'weight': weight, 
            'price': price,
            'unit_price': getattr(cost_per_kg, f"{scrap_type}_cost")
        })
        session['grand_total'] = sum(item['price'] for item in session['cart'])

        return redirect(url_for('payment_page'))
    else:
        return "Scrap not available in the requested quantity.", 400

@app.route('/create_order', methods=['POST'])
@login_required
def create_order():
    if 'cart' not in session:
        return jsonify({"error": "Cart is empty"}), 400
    
    total_amount = int(session.get('grand_total', 0) * 100)  # Convert to paise
    if total_amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    try:
        # Create Razorpay order
        order_data = {
            'amount': total_amount,
            'currency': 'INR',
            'receipt': f'order_{random.randint(1000, 9999)}',
            'payment_capture': 1
        }
        
        order = client.order.create(data=order_data)
        
        return jsonify({
            'order_id': order['id'],
            'amount': order['amount'],
            'currency': order['currency']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/payment_page')
def payment_page():
    if 'cart' not in session or not session['cart']:
        return redirect(url_for('buyer_dashboard'))
    
    return render_template("payment_page.html", 
                         cart_items=session['cart'], 
                         grand_total=session['grand_total'],
                         razorpay_key_id=RAZORPAY_KEY_ID)

@app.route('/payment_success', methods=['POST'])
@login_required
def payment_success():
    try:
        # Get payment verification data
        payment_id = request.form.get('razorpay_payment_id')
        order_id = request.form.get('razorpay_order_id')
        signature = request.form.get('razorpay_signature')
        
        # Verify payment signature
        client.utility.verify_payment_signature({
            'razorpay_payment_id': payment_id,
            'razorpay_order_id': order_id,
            'razorpay_signature': signature
        })
        
        # Get the available processed scrap
        processed_scrap = ProcessedScrap.query.filter_by(buyer_id=None).first()
        if not processed_scrap:
            flash('No processed scrap available!', 'error')
            return redirect(url_for('buyer_dashboard'))
        
        # Store cart data before clearing
        cart_items = session['cart']
        grand_total = session['grand_total']
        
        # Update available quantities and create purchase records
        for item in cart_items:
            scrap_type = item['type']
            weight = item['weight']
            
            # Check if enough quantity is available
            current_quantity = getattr(processed_scrap, scrap_type) or 0
            if current_quantity < weight:
                flash(f'Not enough {scrap_type} available!', 'error')
                return redirect(url_for('buyer_dashboard'))
            
            # Update available quantity
            new_quantity = current_quantity - weight
            setattr(processed_scrap, scrap_type, new_quantity)
            
            # Create purchase record
            purchase = Purchase(
                scrap_type=scrap_type,
                weight=weight,
                price=item['price'],
                buyer_id=current_user.id,
                payment_status='completed',
                payment_id=payment_id,
                order_id=order_id,
                created_at=datetime.now()
            )
            db.session.add(purchase)
        
        # If all quantities are zero, mark as purchased
        if (processed_scrap.steel == 0 and 
            processed_scrap.aluminium == 0 and 
            processed_scrap.copper == 0):
            processed_scrap.buyer_id = current_user.id
        
        db.session.commit()
        flash('Purchase completed successfully!', 'success')
        
        # Store bill data in session
        session['bill_items'] = cart_items
        session['bill_total'] = grand_total
        
        # Clear cart data
        session.pop('cart', None)
        session.pop('grand_total', None)
        
        # Redirect to bill page
        return redirect(url_for('bill'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing purchase: {str(e)}', 'error')
        return redirect(url_for('buyer_dashboard'))

@app.route('/bill')
@login_required
def bill():
    if 'bill_items' not in session or 'bill_total' not in session:
        flash('No bill data available!', 'error')
        return redirect(url_for('buyer_dashboard'))
    
    cart_items = session['bill_items']
    grand_total = session['bill_total']
    
    # Clear bill data from session after rendering
    session.pop('bill_items', None)
    session.pop('bill_total', None)
    
    return render_template('bill.html', 
                         cart_items=cart_items, 
                         grand_total=grand_total)

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))

@app.route('/recycler_dashboard', methods=['GET', 'POST'])
@login_required
def recycler_dashboard():
    if current_user.role != 'recycler':
        flash('Access denied. Recycler privileges required.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_scrap = Scrap(
            name=request.form['name'],
            condition=request.form['type'],
            weight=float(request.form['weight']),
            price=float(request.form['price']),
            pickup_date=datetime.strptime(request.form['pickup_date'], '%Y-%m-%d').date(),
            pickup_slot=request.form['pickup_slot'],
            user_id=current_user.id
        )
        db.session.add(new_scrap)
        db.session.commit()
    
    recycler_scraps = Scrap.query.filter_by(user_id=current_user.id).all()
    return render_template("recycler_dashboard.html", scrap_data=recycler_scraps)

@app.route('/test-db')
def test_db():
    try:
        # Try to query the database
        user_count = User.query.count()
        return jsonify({
            'status': 'success',
            'message': f'Database connection successful. User count: {user_count}',
            'database_url': app.config['SQLALCHEMY_DATABASE_URI'].split('@')[-1] if '@' in app.config['SQLALCHEMY_DATABASE_URI'] else 'sqlite'
        })
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Database connection failed: {str(e)}',
            'database_url': app.config['SQLALCHEMY_DATABASE_URI'].split('@')[-1] if '@' in app.config['SQLALCHEMY_DATABASE_URI'] else 'sqlite'
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)