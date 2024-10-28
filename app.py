from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import random
import string
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///credit_union.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from flask_mail import Mail, Message

# Add this configuration after creating the Flask app
app.config['MAIL_SERVER'] = 'mail.raydexhub.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('Raydex Hub', os.getenv('MAIL_USERNAME'))
app.config['MAIL_DEBUG'] = True

mail = Mail(app)

# Add this function to send emails
def send_email(subject, recipient, body):
    msg = Message(subject, recipients=[recipient])
    msg.body = body
    mail.send(msg)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    national_id = db.Column(db.String(20), unique=True, nullable=False)
    account_number = db.Column(db.String(20), unique=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    other_names = db.Column(db.String(50), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=False)
    occupation = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    national_id_file = db.Column(db.String(255), nullable=True)  # File path to uploaded National ID
    
    contributions = db.relationship('Contribution', backref='user', lazy=True)
    loans = db.relationship('Loan', backref='user', lazy=True, foreign_keys='Loan.user_id')
    guarantees = db.relationship('Loan', backref='guarantor', lazy=True, foreign_keys='Loan.guarantor_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'other_names': self.other_names,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'national_id': self.national_id,
            'occupation': self.occupation,
            'phone_number': self.phone_number,
            'address': self.address,
            'city': self.city,
            'state': self.state,
            'country': self.country,
            'national_id_file': self.national_id_file,
        }

    
    def __repr__(self):
        return f'<User {self.account_number}>'


class Contribution(db.Model):
    __tablename__ = 'contribution'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Contribution {self.amount} by User {self.user_id} on {self.date}>'


class Loan(db.Model):
    __tablename__ = 'loan'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # User who is taking the loan
    amount = db.Column(db.Float, nullable=False)
    purpose = db.Column(db.String(200), nullable=False)
    guarantor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Guarantor for the loan
    term = db.Column(db.Integer, nullable=False)  # Loan term in months
    income = db.Column(db.Float, nullable=False)  # Monthly income of the applicant
    status = db.Column(db.String(20), default='pending')  # Status: pending, approved, rejected
    application_date = db.Column(db.DateTime, default=datetime.utcnow)
    approval_date = db.Column(db.DateTime, nullable=True)  # Date when loan is approved/rejected
    repayment_date = db.Column(db.DateTime, nullable=True)  # Date when loan should be repaid

    def approve_loan(self):
        self.status = 'approved'
        self.approval_date = datetime.utcnow()

    def reject_loan(self):
        self.status = 'rejected'
        self.approval_date = datetime.utcnow()

    def __repr__(self):
        return f'<Loan {self.amount} for User {self.user_id}, Status: {self.status}>'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

from datetime import datetime

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        other_names = request.form.get('other_names')
        email = request.form.get('email')
        password = request.form.get('password')
        national_id = request.form.get('national_id')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        other_names = request.form.get('other_names')
        date_of_birth_str = request.form.get('date_of_birth')  # Get the date as a string
        occupation = request.form.get('occupation')
        phone_number = request.form.get('phone_number')
        address = request.form.get('address')
        city = request.form.get('city')
        state = request.form.get('state')
        country = request.form.get('country')

        # Convert the date string to a Python date object
        date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date()

        existing_user = User.query.filter( (User.email == email)).first()
        if existing_user:
            flash('Email already exists.', 'error')
            return redirect(url_for('register'))

        new_user = User(other_names=other_names, email=email, national_id=national_id,
                        first_name=first_name, last_name=last_name, date_of_birth=date_of_birth,
                        occupation=occupation, phone_number=phone_number, address=address,
                        city=city, state=state, country=country)
        new_user.set_password(password)

        # Handle file upload
        if 'national_id_upload' in request.files:
            file = request.files['national_id_upload']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                new_user.national_id_file = file_path

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login successful.', 'success')
            if not user.is_verified:
                flash('Your account is not yet verified. Some features may be limited.', 'warning')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

def generate_account_number():
    return 'UCU' + ''.join(random.choices(string.digits, k=8))

@app.route('/admin/verify_users', methods=['GET'])
def admin_verify_users():
    users = User.query.filter_by(is_verified=False).all()
    users_dict = [user.to_dict() for user in users]  # Convert User objects to dictionaries
    return render_template('admin_verify_users.html', users=users_dict)

@app.route('/admin/user_details/<int:user_id>', methods=['GET'])
def user_details(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_details.html', user=user)

@app.route('/admin/verify_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def verify_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    user.is_verified = True
    user.account_number = generate_account_number()

    try:
        db.session.commit()
        print("Database commit successful.")
    except Exception as e:
        print(f"Error during commit: {e}")
        flash('There was an error verifying the user. Please try again later.', 'error')
        return redirect(url_for('admin_verify_users'))

    # Send email notification to user
    subject = 'Your UCU_Unity_Can_Unite Account Has Been Verified'
    body = f"""
    Dear {user.first_name} {user.last_name},

    YUCU_Unity_Can_Unite account has been verified. Your account number is {user.account_number}.

    You can now access all features of our services.

    Best regards,
    Credit Union Team
    """
    
    try:
        send_email(subject, user.email, body)
        print("Email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")
        flash('User has been verified, but there was an issue sending the email notification.', 'warning')

    flash(f'User {user.first_name} {user.last_name} has been verified.', 'success')
    return redirect(url_for('admin_verify_users'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/contribute', methods=['GET', 'POST'])
@login_required
def contribute():
    if not current_user.is_verified:
        flash('Your account needs to be verified before you can make contributions.', 'warning')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        amount = float(request.form.get('amount'))
        contribution = Contribution(user_id=current_user.id, amount=amount)
        db.session.add(contribution)
        db.session.commit()
        flash('Contribution added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('contribute.html')

@app.route('/loan_application', methods=['GET', 'POST'])
@login_required
def loan_application():
    # Check if the user account is verified
    if not current_user.is_verified:
        flash('Your account needs to be verified before you can apply for loans.', 'warning')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Validate form data
        try:
            amount = float(request.form.get('amount'))
            purpose = request.form.get('purpose')
            guarantor_email = request.form.get('guarantor')
            term = int(request.form.get('term'))
            income = float(request.form.get('income'))

            # Check if the amount and income are positive values
            if amount <= 0 or income <= 0:
                flash('Loan amount and monthly income must be greater than zero.', 'error')
                return render_template('loan_application.html')

            # Find the guarantor by username
            guarantor = User.query.filter_by(email=guarantor_email).first()
            if not guarantor:
                flash('Guarantor not found. Please enter a valid email.', 'error')
                return render_template('loan_application.html')

            # Create and submit the loan application
            loan = Loan(user_id=current_user.id, amount=amount, purpose=purpose, guarantor_id=guarantor.id, term=term, income=income)
            db.session.add(loan)
            db.session.commit()

            flash('Loan application submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        except ValueError:
            flash('Invalid input. Please enter numeric values for amount and income.', 'error')
            return render_template('loan_application.html')
        
        except Exception as e:
            db.session.rollback()  # Rollback the session on error
            flash('An error occurred while submitting your application. Please try again.', 'error')
            app.logger.error(f'Error during loan application submission: {e}')

    return render_template('loan_application.html')


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    # Check if the current user is an admin
    if not current_user.is_admin:
        flash('Access denied! Admins only.', 'danger')
        return redirect(url_for('home'))
    
    # Fetch data dynamically (you would replace these with real queries)
    total_users = User.query.count()
    pending_verifications = User.query.filter_by(is_verified=False).count()
    pending_loans = Loan.query.filter_by(status='pending').count()
    
    # Dummy recent activities for illustration
    recent_activities = [
        {'timestamp': datetime.now(), 'description': 'New user registration.'},
        {'timestamp': datetime.now(), 'description': 'Loan request submitted.'},
        # Add more activities as needed
    ]
    
    return render_template('admin_dashboard.html', 
                           total_users=total_users, 
                           pending_verifications=pending_verifications, 
                           pending_loans=pending_loans, 
                           recent_activities=recent_activities)

@app.route('/admin/loan_requests')
@login_required
def admin_loan_requests():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('dashboard'))
    
    pending_loans = Loan.query.filter_by(status='pending').all()
    return render_template('admin_loan_requests.html', loans=pending_loans)

@app.route('/admin/approve_loan/<int:loan_id>', methods=['GET'])
@login_required
def approve_loan(loan_id):
    # Check if the user is an admin
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))
    
    # Fetch the loan using the provided loan_id
    loan = Loan.query.get_or_404(loan_id)

    # Update the loan status to approved
    loan.approve_loan()  # Using the method you defined in the Loan class
    db.session.commit()
    
    # Prepare the email notification content
    subject = 'Your Loan Application Has Been Approved'
    body = f"""
    Dear {loan.user.first_name} {loan.user.last_name},

    Your loan application for ${loan.amount:.2f} has been approved.

    Purpose: {loan.purpose}
    Application Date: {loan.application_date.strftime('%Y-%m-%d')}
    
    Please log in to your account for more details.

    Best regards,
    Credit Union Team
    """
    
    # Send email notification to user
    try:
        send_email(subject, loan.user.email, body)
    except Exception as e:
        flash('There was an error sending the notification email.', 'error')
        app.logger.error(f'Error sending email to {loan.user.email}: {e}')

    flash(f'Loan for user {loan.user.first_name} {loan.user.last_name} has been approved and notified via email.', 'success')
    return redirect(url_for('admin_loan_requests'))


if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()

        # Insert users if they don't already exist
        if not User.query.filter_by(email='agyareyraphael@gmail.com').first():
            user1 = User(other_names='testuser', email='agyareyraphael@gmail.com', 
                         first_name='Test', last_name='User', date_of_birth=datetime(1990, 1, 1), 
                         occupation='Developer', phone_number='1234567890', address='123 Street',
                         city='City', state='State', country='Country', 
                         national_id='1234567890123')
            user1.set_password('password')
            db.session.add(user1)

        if not User.query.filter_by(email='raphaelagyarey@gmail.com').first():
            user2 = User(other_names='testuser2', email='raphaelagyarey@gmail.com', 
                         first_name='Test2', last_name='User2', date_of_birth=datetime(1992, 2, 2), 
                         occupation='Designer', phone_number='0987654321', address='456 Avenue',
                         city='Another City', state='Another State', country='Another Country', 
                         national_id='9876543210987')
            user2.set_password('password')
            db.session.add(user2)

        if not User.query.filter_by(email='info@raydexhub.com').first():
            admin = User(other_names='admin', email='info@raydexhub.com', 
                         first_name='Admin', last_name='User', date_of_birth=datetime(1985, 5, 5), 
                         occupation='Admin', phone_number='1231231234', address='Admin Street',
                         city='Admin City', state='Admin State', country='Admin Country', 
                         national_id='0000000000000', is_admin=True)
            admin.set_password('adminpassword')
            db.session.add(admin)

        db.session.commit()

    app.run(debug=True)
