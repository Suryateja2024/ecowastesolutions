from app import app, db
from models import User, Scrap, ProcessedScrap, CostPerKg, Purchase

def reset_database():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        print("All tables dropped successfully!")
        
        # Create all tables
        db.create_all()
        print("All tables created successfully!")
        
        # Create default users
        admin = User(
            username='admin',
            password='admin123',
            role='admin'
        )
        processor = User(
            username='processor',
            password='processor123',
            role='processor'
        )
        buyer = User(
            username='buyer',
            password='buyer123',
            role='buyer'
        )
        
        db.session.add(admin)
        db.session.add(processor)
        db.session.add(buyer)
        
        # Create default cost settings
        cost_settings = CostPerKg(
            steel_cost=12,
            aluminium_cost=10,
            copper_cost=8
        )
        db.session.add(cost_settings)
        
        db.session.commit()
        print("Default users and cost settings created successfully!")

if __name__ == '__main__':
    reset_database() 