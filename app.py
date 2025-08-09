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
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Flask-Mail Configuration ---
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER')
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# --- OAuth Configuration for Google ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
)

# --- Stripe Configuration ---
# Your secret API key is used to authenticate with Stripe's API.
# It should be loaded from your .env file.
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')


# --- User Model ---
# This is a basic User model for the database.
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    is_activated = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# --- Routes ---

@app.route('/')
def index():
    """Renders the main index page."""
    return render_template('index.html')


# --- User Login Route ---
# The change here is adding 'POST' to the methods list to handle form submissions.
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Renders the login page and handles login form submissions."""
    if request.method == 'POST':
        # Now correctly handling a JSON payload from the frontend fetch request.
        data = request.json
        email = data.get('email')
        password = data.get('password')

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            if not user.is_verified:
                # Return a JSON response instead of flashing a message.
                return jsonify({'success': False, 'message': 'Please verify your email first.'})

            # Set the user data in the session
            session['user'] = {
                'name': user.name,
                'email': user.email,
                'is_verified': user.is_verified,
                'is_activated': user.is_activated
            }

            # Return a JSON response with a redirect URL.
            redirect_url = url_for('profile') if user.is_activated else url_for('activate')
            return jsonify({'success': True, 'message': 'Login successful!', 'redirect': redirect_url})
        else:
            # Return a JSON response for invalid credentials.
            return jsonify({'success': False, 'message': 'Invalid email or password.'})

    # This part of the code handles the initial GET request for the login page.
    return render_template('login.html', page_name='login')


@app.route('/register', methods=['POST'])
def register():
    """Handles user registration."""
    try:
        data = request.json
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')

        if not all([name, email, password]):
            return jsonify({'success': False, 'message': 'Missing fields.'})

        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already exists.'})

        user = User(name=name, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # After successful registration, send a verification email
        send_verification_email(user.email)

        return jsonify({
            'success': True,
            'message': 'Registration successful! A verification email has been sent.'
        })

    except Exception as e:
        print(f"Registration failed: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An unexpected error occurred.'}), 500


@app.route('/send_verification_email/<email>')
def send_verification_email(email):
    """Sends an email with a verification link."""
    try:
        token = s.dumps(email, salt='email-confirm')
        msg = Message('Confirm Your Account', recipients=[email])
        link = url_for('confirm_email', token=token, _external=True)
        msg.body = f'Your link is {link}'
        mail.send(msg)
        return jsonify({'success': True, 'message': 'Verification email sent.'})
    except Exception as e:
        print(f"Failed to send email: {e}")
        return jsonify({'success': False, 'message': 'Failed to send verification email.'})


@app.route('/confirm_email/<token>')
def confirm_email(token):
    """Confirms a user's email address using a token."""
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(email=email).first_or_404()
        user.is_verified = True
        db.session.commit()
        flash('Account successfully verified!', 'success')
    except Exception as e:
        flash('The confirmation link is invalid or has expired.', 'error')
    return redirect(url_for('login'))


@app.route('/profile')
def profile():
    """Renders the user's profile page."""
    if 'user' in session:
        return render_template('profile.html', user=session['user'])
    flash('Please log in to view your profile.', 'warning')
    return redirect(url_for('login'))


@app.route('/google_login')
def google_login():
    """Initiates the Google OAuth login process."""
    return google.authorize_redirect(url_for('google_callback', _external=True))


@app.route('/google_callback')
def google_callback():
    """Handles the callback from Google OAuth."""
    try:
        token = google.authorize_access_token()
        user_info = google.get('userinfo').json()

        user = User.query.filter_by(email=user_info.get('email')).first()
        if not user:
            user = User(name=user_info.get('name'), email=user_info.get('email'), is_verified=True, is_activated=False)
            user.set_password(os.urandom(16).hex())
            db.session.add(user)
            db.session.commit()
        else:
            user.is_verified = True
            db.session.commit()

        session['user'] = {
            'name': user.name,
            'email': user.email,
            'is_verified': user.is_verified,
            'is_activated': user.is_activated
        }

        flash('Google login successful!', 'success')
        return redirect(url_for('profile'))

    except Exception as e:
        print(f"OAuth callback failed: {e}")
        flash('Google login failed.', 'error')
        return redirect(url_for('login'))


@app.route('/activate')
def activate():
    """Renders the account activation/subscription page."""
    if 'user' not in session:
        flash('Please log in to activate your account.', 'warning')
        return redirect(url_for('login'))
    return render_template('activate.html')


@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/create-payment', methods=['POST'])
def create_payment():
    """
    Handles payment requests from the frontend using Stripe.
    It receives the payment method ID, creates a PaymentIntent,
    and updates the user's activation status upon success.
    """
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    try:
        data = request.json
        payment_method_id = data.get('paymentMethodId')
        plan = data.get('plan')
        amount = 0

        # Set the amount based on the selected plan. Amounts are in cents.
        if plan == 'monthly':
            amount = 800  # $8.00
        elif plan == 'yearly':
            amount = 4500  # $45.00
        else:
            return jsonify({'success': False, 'message': 'Invalid plan selected'}), 400

        # Create a PaymentIntent with Stripe
        intent = stripe.PaymentIntent.create(
            amount=amount,
            currency='usd',
            payment_method=payment_method_id,
            confirm=True,
            metadata={'user_email': session['user']['email'], 'plan': plan}
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
