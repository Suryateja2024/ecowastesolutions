from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Scrap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    condition = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    price = db.Column(db.Float, nullable=False)
    pickup_date = db.Column(db.Date, nullable=False)
    pickup_slot = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    image_path = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationship with User model
    user = db.relationship('User', backref=db.backref('scraps', lazy=True))

class ProcessedScrap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    steel = db.Column(db.Float, default=0)
    aluminium = db.Column(db.Float, default=0)
    copper = db.Column(db.Float, default=0)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    buyer = db.relationship('User', backref=db.backref('processed_scraps', lazy=True))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class CostPerKg(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    steel_cost = db.Column(db.Float, default=12)
    aluminium_cost = db.Column(db.Float, default=10)
    copper_cost = db.Column(db.Float, default=8)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scrap_type = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    price = db.Column(db.Float, nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payment_status = db.Column(db.String(20), default='pending')
    payment_id = db.Column(db.String(100))  # Razorpay payment ID
    order_id = db.Column(db.String(100))    # Razorpay order ID
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    buyer = db.relationship('User', backref=db.backref('purchases', lazy=True))
