from app import app, db, User
from datetime import datetime

def init_db():
    with app.app_context():
        # Drop all existing tables
        db.drop_all()
        
        # Create all tables
        db.create_all()
        
        # Create sample users
        sample_users = [
            {
                'email': 'info@raydexhub.com',
                'password': 'adminpassword',
                'first_name': 'UCU',
                'last_name': 'Admin',
                'other_names': 'Unity Can Unite',
                'date_of_birth': datetime(1985, 5, 5),
                'occupation': 'Admin',
                'phone_number': '0247767438',
                'address': 'Admin Street',
                'city': 'Admin City',
                'state': 'Admin State',
                'country': 'Admin Country',
                'national_id': '0000000000000',
                'is_admin': True
            }
        ]

        # Insert users if they don't already exist
        for user_data in sample_users:
            if not User.query.filter_by(email=user_data['email']).first():
                user = User(
                    email=user_data['email'],
                    first_name=user_data['first_name'],
                    last_name=user_data['last_name'],
                    other_names=user_data['other_names'],
                    date_of_birth=user_data['date_of_birth'],
                    occupation=user_data['occupation'],
                    phone_number=user_data['phone_number'],
                    address=user_data['address'],
                    city=user_data['city'],
                    state=user_data['state'],
                    country=user_data['country'],
                    national_id=user_data['national_id'],
                    is_admin=user_data['is_admin']
                )
                user.set_password(user_data['password'])
                db.session.add(user)

        # Commit all changes
        try:
            db.session.commit()
            print("Database initialized successfully!")
        except Exception as e:
            db.session.rollback()
            print(f"Error initializing database: {e}")

if __name__ == '__main__':
    init_db()