# app.py

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from authlib.integrations.flask_client import OAuth
import os
import datetime
from dotenv import load_dotenv
import stripe

# Load environment variables from the .env file
load_dotenv()

# --- Application Initialization ---
app = Flask(__name__)

# A secret key is required for session management and token serialization.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_strong_secret_key_123')

# --- Database Configuration ---
# Use an environment variable for the database URI for flexibility
# This allows us to use a local SQLite DB for development and a PostgreSQL DB for production
# This is a major change from your previous code to make the app work on Render
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# --- User Model ---
# We are moving the User model directly into app.py to avoid the circular import.
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # password_hash is nullable for users who sign up via OAuth
    password_hash = db.Column(db.String(128), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    is_activated = db.Column(db.Boolean, default=False)  # New column for account activation status

    def set_password(self, password):
        """Hashes the password and sets the password_hash."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email}>'


# --- Flask-Mail Configuration ---
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER')
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# --- Stripe Configuration ---
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

# --- OAuth Configuration ---
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid profile email'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)


# A custom alert function to handle messages without using alert()
def custom_alert(title, message, redirect_url=None):
    return render_template('custom_alert.html', title=title, message=message, redirect_url=redirect_url)


def is_logged_in():
    return 'user' in session


def is_verified():
    if 'user' in session:
        user = User.query.filter_by(email=session['user']['email']).first()
        return user and user.is_verified
    return False


def is_activated():
    if 'user' in session:
        user = User.query.filter_by(email=session['user']['email']).first()
        return user and user.is_activated
    return False


# --- Routes ---

# Home page route
@app.route('/')
def index():
    user_name = session.get('user', {}).get('name')
    is_authenticated = 'user' in session
    return render_template('index.html', user_name=user_name, is_authenticated=is_authenticated)


# Login and Registration page route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('index'))

    return render_template('login.html')


# Email verification route
@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            db.session.commit()
            flash('Your email has been verified successfully!', 'success')
        else:
            flash('Verification link is invalid.', 'danger')
    except Exception as e:
        flash('The verification link is expired or invalid.', 'danger')

    return redirect(url_for('login'))


# Activation page route (requires email to be verified)
@app.route('/activate')
def activate():
    if not is_logged_in() or not is_verified():
        return redirect(url_for('login'))

    if is_activated():
        return redirect(url_for('profile'))

    return render_template('activate.html')


# Profile page route (requires activation)
@app.route('/profile')
def profile():
    if not is_logged_in() or not is_verified() or not is_activated():
        return redirect(url_for('login'))

    user_name = session['user']['name']
    user_email = session['user']['email']

    return render_template('profile.html', user_name=user_name, user_email=user_email)


# Logout route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


# Endpoint for manual email registration
@app.route('/register_email', methods=['POST'])
def register_email():
    name = request.json.get('name')
    email = request.json.get('email')
    password = request.json.get('password')

    if not all([name, email, password]):
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'success': False, 'message': 'Email already registered.'}), 409

    new_user = User(name=name, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    token = s.dumps(email, salt='email-confirm')
    msg = Message('Confirm Your Email',
                  recipients=[email],
                  body=f'Click the link to verify your email: {url_for("verify_email", token=token, _external=True)}')
    mail.send(msg)

    return jsonify(
        {'success': True, 'message': 'Registration successful. Please check your email to verify your account.'})


# OAuth login with Google
@app.route('/google_login')
def google_login():
    if 'user' in session:
        return redirect(url_for('index'))

    redirect_uri = url_for('authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


# OAuth authorization callback
@app.route('/authorize')
def authorize():
    try:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.get('userinfo').json()

        email = user_info['email']
        user = User.query.filter_by(email=email).first()

        if not user:
            user = User(
                name=user_info.get('name'),
                email=email,
                is_verified=True  # OAuth users are considered verified
            )
            db.session.add(user)
            db.session.commit()

        # Store user info in session
        session['user'] = {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'is_verified': user.is_verified,
            'is_activated': user.is_activated
        }

        if not user.is_activated:
            return redirect(url_for('activate'))

        return redirect(url_for('index'))
    except Exception as e:
        print(f"OAuth error: {e}")
        return redirect(url_for('login'))


@app.route('/create-payment', methods=['POST'])
def create_payment():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'User not authenticated'}), 401

    try:
        data = request.get_json()
        payment_method_id = data.get('paymentMethodId')
        plan = data.get('plan')

        # Define plan prices in cents
        if plan == 'monthly':
            amount = 1000  # $10.00
        else:
            return jsonify({'success': False, 'message': 'Invalid plan selected'}), 400

        # Create a PaymentIntent with the provided payment method and amount
        intent = stripe.PaymentIntent.create(
            amount=amount,
            currency='usd',
            payment_method=payment_method_id,
            confirmation_method='manual',
            confirm=True,
            description=f"Payment for {plan} plan for {session['user']['email']}",
            return_url='https://super-sales-manager.onrender.com/'  # The public URL of your app
        )

        # Check the status of the PaymentIntent
        if intent.status == 'succeeded':
            # Payment was successful. Update the user's activation status in the database.
            user = User.query.filter_by(email=session['user']['email']).first()
            if user:
                user.is_activated = True
                db.session.commit()
                # Update the session to reflect the change
                session['user']['is_activated'] = True
            else:
                return jsonify({'success': False, 'message': 'User not found in database'}), 404

            return jsonify({'success': True, 'message': 'Payment successful and account activated!'})
        else:
            # Handle other possible statuses, like 'requires_action'
            return jsonify({'success': False, 'message': 'Payment requires additional action.'})

    except stripe.error.CardError as e:
        # A decline or other card-related error occurred
        return jsonify({'success': False, 'message': e.user_message})
    except Exception as e:
        # Handle any other unexpected errors
        print(f"An error occurred: {e}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred.'}), 500


if __name__ == '__main__':
    # Initialize the database and create tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)
