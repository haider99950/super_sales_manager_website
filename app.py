# app.py
import os
import secrets
from datetime import datetime, timedelta
from urllib.parse import urljoin
import stripe

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

# --- App Initialization and Configuration ---
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Flask-Mail configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("EMAIL_USER")
app.config["MAIL_PASSWORD"] = os.environ.get("EMAIL_PASS")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("EMAIL_USER")

# Stripe configuration
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_MONTHLY_PLAN_ID = "price_1Ovz0bT69G6FvJ7b5D6u9H2i" # Replace with your actual price IDs
STRIPE_ANNUAL_PLAN_ID = "price_1Ovz0bT69G6FvJ7b5J6u8T2k" # Replace with your actual price IDs
STRIPE_SUCCESS_URL = "http://localhost:5000/profile?session_id={CHECKOUT_SESSION_ID}"
STRIPE_CANCEL_URL = "http://localhost:5000/pricing"

# Google OAuth configuration
app.config["GOOGLE_CLIENT_ID"] = os.environ.get("GOOGLE_CLIENT_ID")
app.config["GOOGLE_CLIENT_SECRET"] = os.environ.get("GOOGLE_CLIENT_SECRET")
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # For local testing with http

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"
s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
oauth = OAuth(app)

oauth.register(
    name="google",
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url="https://oauth2.googleapis.com/token",
    access_token_params=None,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    api_base_url="https://www.googleapis.com/oauth2/v1/",
    userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=True)
    is_google_user = db.Column(db.Boolean, default=False)
    verified = db.Column(db.Boolean, default=False)
    subscription_status = db.Column(db.String(20), default="Free") # Can be 'Free', 'Monthly', 'Annually'

    def get_id(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        return self.is_active

    @property
    def is_active(self):
        return self.verified

    @property
    def is_anonymous(self):
        return False

    def __repr__(self):
        return f"User('{self.email}', '{self.subscription_status}')"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Routes ---
@app.route("/")
@app.route("/home")
def home():
    return render_template("index.html", title="Home")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        # Create a new user but don't set 'verified' to True yet
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Send verification email
        send_verification_email(email)
        flash(
            "A verification email has been sent to your email address. Please verify to log in.",
            "info",
        )
        return redirect(url_for("login"))
    return render_template("register.html", title="Register")


def send_verification_email(email):
    token = s.dumps(email, salt="email-confirm-salt")
    verification_link = url_for("verify_email", token=token, _external=True)
    msg = Message(
        "Verify Your Email Address",
        recipients=[email],
    )
    msg.body = f"""Hello,

Thank you for registering with Super Sales Manager!
Please click the following link to verify your email address:
{verification_link}

If you did not make this request, please ignore this email.
"""
    mail.send(msg)


@app.route("/verify_email/<token>")
def verify_email(token):
    try:
        email = s.loads(token, salt="email-confirm-salt", max_age=3600)  # Token valid for 1 hour
    except:
        flash("The verification link is invalid or has expired.", "danger")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if user and not user.verified:
        user.verified = True
        db.session.commit()
        flash("Your account has been verified! You can now log in.", "success")
    elif user and user.verified:
        flash("Your account has already been verified.", "info")
    else:
        flash("Verification failed. User not found.", "danger")

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and user.password_hash and bcrypt.check_password_hash(user.password_hash, password):
            if user.verified:
                login_user(user)
                return redirect(url_for("profile"))
            else:
                flash("Please verify your email address to log in.", "warning")
        else:
            flash("Login Unsuccessful. Please check email and password", "danger")
    return render_template("login.html", title="Login")


@app.route("/login/google")
def login_google():
    redirect_uri = url_for("authorize_google", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/login/google/authorize")
def authorize_google():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)
    user = User.query.filter_by(email=user_info["email"]).first()
    if not user:
        new_user = User(email=user_info["email"], is_google_user=True, verified=True)
        db.session.add(new_user)
        db.session.commit()
        user = new_user
    login_user(user)
    return redirect(url_for("profile"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", title="Profile")


@app.route("/pricing")
def pricing():
    return render_template("pricing.html", title="Pricing")


@app.route("/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    price_id = request.form.get("price_id")
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    "price": price_id,
                    "quantity": 1,
                },
            ],
            mode="subscription",
            success_url=STRIPE_SUCCESS_URL.format(CHECKOUT_SESSION_ID="{CHECKOUT_SESSION_ID}"),
            cancel_url=STRIPE_CANCEL_URL,
            customer_email=current_user.email
        )
        return jsonify({"id": checkout_session.id})
    except Exception as e:
        return jsonify(error=str(e)), 403


@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    # This is a very basic webhook endpoint. For production, you should
    # verify the signature of the incoming request.
    # See https://stripe.com/docs/webhooks/signatures for more details.
    payload = request.get_data()
    event = None

    try:
        event = stripe.Event.construct_from(
            payload, stripe.api_key
        )
    except ValueError as e:
        # Invalid payload
        print(f"Webhook Error: Invalid payload - {e}")
        return "", 400

    # Handle the event
    if event.type == "checkout.session.completed":
        session = event.data.object
        customer_email = session.customer_details.email
        user = User.query.filter_by(email=customer_email).first()
        if user:
            price_id = session.line_items.data[0].price.id
            if price_id == STRIPE_MONTHLY_PLAN_ID:
                user.subscription_status = "Monthly"
            elif price_id == STRIPE_ANNUAL_PLAN_ID:
                user.subscription_status = "Annually"
            else:
                user.subscription_status = "Free" # fallback
            db.session.commit()
            print(f"Subscription for {customer_email} updated to {user.subscription_status}")
    else:
        # For other event types, we can ignore them for this basic example.
        print(f"Unhandled event type {event.type}")

    return "", 200

# To run this script, you must initialize the database first.
# You can do this by running `python` in your terminal and typing:
# `from app import db; db.create_all()`
# This will create the `site.db` file in your project directory.
# If you make changes to the models, you will need to delete the `site.db` file and run `db.create_all()` again.

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

