from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort, Blueprint
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import case
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import random
import string
from datetime import datetime, timedelta
from dotenv import load_dotenv
import re
from functools import wraps
from itsdangerous import URLSafeTimedSerializer

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['RESET_TOKEN_SECRET_KEY'] = os.getenv('RESET_TOKEN_SECRET_KEY', 'your-secret-key')
app.config['RESET_TOKEN_SALT'] = os.getenv('RESET_TOKEN_SALT', 'password-reset-salt')
app.config['RESET_TOKEN_MAX_AGE'] = 3600  # 1 hour expiration
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
db = SQLAlchemy(app)
migrate = Migrate(app, db)
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
application = app

# Add this function to send emails
def send_email(subject, recipient, body):
    msg = Message(subject, recipients=[recipient])
    msg.body = body
    mail.send(msg)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)  # Made nullable
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_guest = db.Column(db.Boolean, default=False)  # New field to identify non-member users
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
    national_id_file = db.Column(db.String(255), nullable=True)
    passport_photo = db.Column(db.String(255), nullable=True)  # New field for passport photo
    
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


class MonthlySavingsTarget(db.Model):
    __tablename__ = 'monthly_savings_target'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_amount = db.Column(db.Float, nullable=False)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<MonthlySavingsTarget {self.target_amount} for User {self.user_id}>'

class Contribution(db.Model):
    __tablename__ = 'contribution'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    contribution_type = db.Column(db.String(20), default='regular')  # 'regular' or 'monthly_savings'
    month = db.Column(db.String(7), nullable=False)  # Format: YYYY-MM
    
    def __repr__(self):
        return f'<Contribution {self.amount} by User {self.user_id} on {self.date}>'


class Loan(db.Model):
    __tablename__ = 'loan'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=True)
    total_amount = db.Column(db.Float, nullable=True)
    amount_paid = db.Column(db.Float, default=0.0)
    remaining_amount = db.Column(db.Float, nullable=True)
    purpose = db.Column(db.String(200), nullable=False)
    guarantor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    term = db.Column(db.Integer, nullable=False)
    income = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # Status can now be: 'pending', 'approved', 'rejected', 'paid'
    application_date = db.Column(db.DateTime, default=datetime.utcnow)
    approval_date = db.Column(db.DateTime, nullable=True)
    repayment_date = db.Column(db.DateTime, nullable=True)
    paid_date = db.Column(db.DateTime, nullable=True)  # New column to track when loan was fully paid

    @staticmethod
    def get_active_loan(user_id):
        return Loan.query.filter(
            Loan.user_id == user_id,
            Loan.status == 'approved',
            Loan.remaining_amount > 0
        ).first()

    def approve_loan(self):
        self.status = 'approved'
        self.approval_date = datetime.utcnow()
        
        # Set interest rate based on loan term
        if self.term == 30:  # Emergency loan (30 days)
            self.interest_rate = 0.055  # 5.5% interest
        elif self.term == 47:  # Development Support loan (47 days)
            self.interest_rate = 0.03   # 3% interest
        elif self.term == 150:  # Installment loan (150 days)
            self.interest_rate = 0.10   # 10% interest
        else:
            # Default interest rate for any other term
            self.interest_rate = 0.05   # 5% interest
            
        # Calculate total amount with interest
        self.total_amount = self.amount * (1 + self.interest_rate)
        self.remaining_amount = self.total_amount
        
        # Set repayment date based on term
        self.repayment_date = datetime.utcnow() + timedelta(days=self.term)

    def make_payment(self, payment_amount):
        if payment_amount <= self.remaining_amount:
            self.amount_paid += payment_amount
            self.remaining_amount -= payment_amount
            
            # Check if loan is fully paid
            if self.remaining_amount <= 0:
                self.status = 'paid'
                self.paid_date = datetime.utcnow()  # Record when the loan was fully paid
                self.remaining_amount = 0  # Ensure remaining amount is exactly 0
            return True
        return False

    def reject_loan(self):
        self.status = 'rejected'
        self.approval_date = datetime.utcnow()

    @staticmethod
    def get_paid_loans():
        """Get all paid loans for historical tracking"""
        return Loan.query.filter(Loan.status == 'paid').order_by(Loan.paid_date.desc()).all()

    def __repr__(self):
        return f'<Loan {self.id} - {self.status}>'
    
class MonthlyTransaction(db.Model):
    __tablename__ = 'monthly_transaction'
    
    id = db.Column(db.Integer, primary_key=True)
    month = db.Column(db.String(7), nullable=False)  # Format: YYYY-MM
    file_name = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<MonthlyTransaction {self.month}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('You need to be logged in to access this page.', 'error')
            return redirect(url_for('login'))

        if not current_user.is_admin:
            flash('You do not have permission to perform this action.', 'error')
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)
    return decorated_function


def send_email(subject, recipient, template, **kwargs):
    msg = Message(
        subject,
        sender=('Unity Credit Union', os.getenv('MAIL_USERNAME')),
        recipients=[recipient]
    )
    
    # Add common template variables
    kwargs.update({
        'year': datetime.now().year,
        'recipient_email': recipient
    })
    
    # Render the HTML template
    msg.html = render_template(f'email_templates/{template}.html', **kwargs)
    
    try:
        mail.send(msg)
        print(f"Email sent successfully to {recipient}")
    except Exception as e:
        print(f"Failed to send email: {e}")
        raise e


@app.route('/')
def home():
    return render_template('home.html')


def validate_email(email):
    """Basic email validation using regex"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_unique_filename(original_filename, user_email):
    """Generate a unique filename using user email and timestamp"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    ext = original_filename.rsplit('.', 1)[1].lower()
    return f"id_{user_email}_{timestamp}.{ext}"

@app.route('/view_national_id/<int:user_id>')
@login_required  # Make sure to implement login_required decorator
def view_national_id(user_id):
    # Check if the current user has permission to view this ID
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    if not user.national_id_file:
        abort(404)
    
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], user.national_id_file)
        return send_file(file_path)
    except FileNotFoundError:
        abort(404)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Get form data
            email = request.form.get('email')
            password = request.form.get('password')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            other_names = request.form.get('other_names')
            national_id = request.form.get('national_id')
            date_of_birth_str = request.form.get('date_of_birth')
            occupation = request.form.get('occupation')
            phone_number = request.form.get('phone_number')
            address = request.form.get('address')
            city = request.form.get('city')
            state = request.form.get('state')
            country = request.form.get('country')

            # Validate required fields
            if not all([email, password, first_name, last_name, national_id, date_of_birth_str]):
                flash('Please fill in all required fields.', 'error')
                return redirect(url_for('register'))

            # Check if user already exists
            if User.query.filter_by(email=email).first():
                flash('Email already registered.', 'error')
                return redirect(url_for('register'))

            if User.query.filter_by(national_id=national_id).first():
                flash('National ID already registered.', 'error')
                return redirect(url_for('register'))

            # Convert date string to date object
            try:
                date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid date format.', 'error')
                return redirect(url_for('register'))

            # Create new user
            new_user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                other_names=other_names,
                national_id=national_id,
                date_of_birth=date_of_birth,
                occupation=occupation,
                phone_number=phone_number,
                address=address,
                city=city,
                state=state,
                country=country
            )
            new_user.set_password(password)

            if 'national_id_upload' in request.files:
                file = request.files['national_id_upload']
                if file and file.filename and allowed_file(file.filename):
                    try:
                        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                        
                        filename = generate_unique_filename(file.filename, email)
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        
                        file.save(file_path)
                        new_user.national_id_file = filename
                    except Exception as e:
                        flash('Error uploading ID document. Please try again.', 'error')
                        app.logger.error(f"File upload error: {str(e)}")
                        return redirect(url_for('register'))
                elif file.filename and not allowed_file(file.filename):
                    flash('Invalid file type. Allowed types are: pdf, png, jpg, jpeg', 'error')
                    return redirect(url_for('register'))

            try:
                # Save user to database
                db.session.add(new_user)
                db.session.commit()
                send_email(
                'Your Unity Credit Union Account Has Been Created Successfully',
                email,
                'account_created',
                user=new_user
                )
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Database error: {str(e)}")
                flash('An error occurred during registration. Please try again.', 'error')
                return redirect(url_for('register'))

        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('register'))

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
    print(user.national_id_file)
    return render_template('user_details.html', user=user)

@app.route('/admin/verify_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def verify_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    user.is_verified = True
    user.account_number = generate_account_number()

    try:
        db.session.commit()
        # Send email with new template
        send_email(
            'Your Unity Credit Union Account Has Been Verified',
            user.email,
            'account_verified',
            user=user
        )
        flash(f'User {user.first_name} {user.last_name} has been verified.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('There was an error verifying the user.', 'error')
        app.logger.error(f'Error during user verification: {e}')
    
    return redirect(url_for('admin_verify_users'))


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
    if not current_user.is_verified:
        flash('Your account needs to be verified before you can apply for loans.', 'warning')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount'))
            purpose = request.form.get('purpose')
            guarantor_email = request.form.get('guarantor')
            term = int(request.form.get('term'))
            income = float(request.form.get('income'))

            if amount <= 0 or income <= 0:
                flash('Loan amount and monthly income must be greater than zero.', 'error')
                return render_template('loan_application.html')

            guarantor = User.query.filter_by(email=guarantor_email).first()
            if not guarantor:
                flash('Guarantor not found. Please enter a valid email.', 'error')
                return render_template('loan_application.html')

            loan = Loan(
                user_id=current_user.id,
                amount=amount,
                purpose=purpose,
                guarantor_id=guarantor.id,
                term=term,
                income=income
            )
            db.session.add(loan)
            db.session.commit()

            flash('Loan application submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        except ValueError:
            flash('Invalid input. Please enter numeric values for amount and income.', 'error')
            return render_template('loan_application.html')
        
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while submitting your application. Please try again.', 'error')
            app.logger.error(f'Error during loan application submission: {e}')

    return render_template('loan_application.html')

@app.route('/admin/manage_contributions')
@login_required
@admin_required
def manage_contributions():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.filter_by(is_verified=True).all()
    current_month = datetime.now().strftime('%Y-%m')
    
    user_data = []
    for user in users:
        monthly_target = MonthlySavingsTarget.query.filter_by(
            user_id=user.id, 
            is_active=True
        ).first()
        
        monthly_contribution = Contribution.query.filter_by(
            user_id=user.id,
            month=current_month,
            contribution_type='monthly_savings'
        ).first()
        
        total_contributions = db.session.query(db.func.sum(Contribution.amount))\
            .filter(Contribution.user_id == user.id)\
            .scalar() or 0.0
        
        user_data.append({
            'user': user,
            'monthly_target': monthly_target,
            'monthly_contribution': monthly_contribution,
            'total_contributions': total_contributions
        })
    
    return render_template('admin_manage_contributions.html', 
                         user_data=user_data,
                         current_month=current_month)



@app.route('/admin/record_monthly_contribution/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def record_monthly_contribution(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        amount = float(request.form.get('amount'))
        month = request.form.get('month')
        
        existing_contribution = Contribution.query.filter_by(
            user_id=user_id,
            month=month,
            contribution_type='monthly_savings'
        ).first()
        
        if existing_contribution:
            flash('A contribution has already been recorded for this month', 'error')
            return redirect(url_for('manage_contributions'))
        
        contribution = Contribution(
            user_id=user_id,
            amount=amount,
            contribution_type='monthly_savings',
            month=month
        )
        db.session.add(contribution)
        db.session.commit()
        
        user = User.query.get(user_id)
        flash(f'Monthly contribution recorded for {user.first_name} {user.last_name}', 'success')
        print("worked")
        
        send_email(
            'Monthly Contribution Recorded',
            user.email,
            'monthly_contribution',
            user=user,
            amount=amount,
            month=month
        )
        
    except ValueError:
        flash('Invalid amount specified', 'error')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while recording the contribution', 'error')
        app.logger.error(f'Error recording monthly contribution: {e}')
    
    return redirect(url_for('manage_contributions'))


@app.route('/admin/process_payment/<int:loan_id>', methods=['POST'])
@login_required
@admin_required
def process_payment(loan_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))
    
    loan = Loan.query.get_or_404(loan_id)
    payment_amount = float(request.form.get('payment_amount', 0))
    
    if loan.make_payment(payment_amount):
        try:
            db.session.commit()
            send_email(
                'Loan Payment Received',
                loan.user.email,
                'payment_confirmation',
                user=loan.user,
                loan=loan,
                payment_amount=payment_amount,
                payment_date=datetime.utcnow()
            )
            flash(f'Payment of {payment_amount:.2f} processed successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('There was an error processing the payment.', 'error')
            app.logger.error(f'Error during payment processing: {e}')
    else:
        flash('Invalid payment amount.', 'error')
    
    return redirect(url_for('admin_loan_requests'))

@app.route('/admin/undo_monthly_contribution/<int:contribution_id>', methods=['POST','GET'])
@login_required
@admin_required
def undo_monthly_contribution(contribution_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))

    contribution = Contribution.query.get_or_404(contribution_id)
    user = contribution.user

    try:
        db.session.delete(contribution)
        db.session.commit()
        flash(f'Monthly contribution for {user.first_name} {user.last_name} has been undone.', 'success')

        send_email(
            'Monthly Contribution Reversal',
            user.email,
            'contribution_reversal',
            user=user,
            amount=contribution.amount,
            month=contribution.month
        )

    except Exception as e:
        db.session.rollback()
        flash('An error occurred while undoing the contribution.', 'error')
        app.logger.error(f'Error undoing monthly contribution: {e}')

    return redirect(url_for('manage_contributions'))


@app.route('/admin/undo_loan_payment/<int:loan_id>', methods=['POST', 'GET'])
@login_required
@admin_required
def undo_loan_payment(loan_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))

    loan = Loan.query.get_or_404(loan_id)
    payment_amount = float(request.form.get('payment_amount', 0))
    user = loan.user

    try:
        loan.undo_payment(payment_amount)  # Make sure Loan model has an undo_payment method
        db.session.commit()
        flash(f'Loan payment of {payment_amount:.2f} has been undone for {user.first_name} {user.last_name}.', 'success')

        send_email(
            'Loan Payment Reversal',
            user.email,
            'payment_reversal',
            user=user,
            loan=loan,
            payment_amount=payment_amount,
            reversal_date=datetime.utcnow()
        )

    except Exception as e:
        db.session.rollback()
        flash('An error occurred while undoing the payment.', 'error')
        app.logger.error(f'Error undoing loan payment: {e}')

    return redirect(url_for('manage_loans'))

@app.route('/loan-history')
@login_required
def loan_history():
    paid_loans = Loan.get_paid_loans()
    return render_template('loan_history.html', loans=paid_loans)

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
    
    loans = Loan.query.order_by(
        case(
            (Loan.status == 'pending', 1),
            (Loan.status == 'approved', 2),
            (Loan.status == 'rejected', 3)
        ),
        Loan.application_date.desc()
    ).all()
    print(len(loans))
    
    return render_template('admin_loan_requests.html', loans=loans)

@app.route('/admin/reject_loan/<int:loan_id>', methods=['GET'])
@login_required
def reject_loan(loan_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))
    
    loan = Loan.query.get_or_404(loan_id)
    loan.reject_loan()
    
    try:
        db.session.commit()
        send_email(
            'Loan Application Status Update',
            loan.user.email,
            'loan_rejected',
            loan=loan
        )
        flash(f'Loan for {loan.user.first_name} {loan.user.last_name} has been rejected.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('There was an error rejecting the loan.', 'error')
        app.logger.error(f'Error during loan rejection: {e}')
    
    return redirect(url_for('admin_loan_requests'))

@app.route('/admin/approve_loan/<int:loan_id>', methods=['GET'])
@login_required
def approve_loan(loan_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('dashboard'))
    
    loan = Loan.query.get_or_404(loan_id)
    loan.approve_loan()
    
    try:
        db.session.commit()
        send_email(
            'Your Loan Application Has Been Approved',
            loan.user.email,
            'loan_approved',
            loan=loan
        )
        flash(f'Loan for {loan.user.first_name} {loan.user.last_name} has been approved.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('There was an error approving the loan.', 'error')
        app.logger.error(f'Error during loan approval: {e}')
    
    return redirect(url_for('admin_loan_requests'))


if __name__ == '__main__':
    app.run(debug=False)

