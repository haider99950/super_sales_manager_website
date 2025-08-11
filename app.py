# C:\Users\Administrator\PycharmProjects\app_download_website\app.py
# This file serves as the main application for a Flask web app that manages user
# authentication, subscriptions via Stripe, and generates unique license codes.

import os
import secrets
import stripe
import json
from urllib.parse import urljoin
import requests  # New import to make HTTP requests
from datetime import datetime

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
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

# --- App Initialization and Configuration ---

# Load environment variables from a .env file.
# This is a crucial security practice to keep sensitive keys out of the codebase.
load_dotenv()

app = Flask(__name__)
# The secret key is used for session management and security.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")

# Configure the database to use the DATABASE_URL environment variable.
# Using an environment variable makes the app portable to different environments
# (e.g., local development, production with Neon).
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Stripe configuration, also using environment variables for security.
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")
STRIPE_MONTHLY_PLAN_ID = os.environ.get("STRIPE_MONTHLY_PLAN_ID")
STRIPE_ANNUAL_PLAN_ID = os.environ.get("STRIPE_ANNUAL_PLAN_ID")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

# This new environment variable holds the URL of your deployed code generator service.
CODE_GENERATOR_URL = os.environ.get("CODE_GENERATOR_URL")

# Flask-Login configuration for managing user sessions.
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# Bcrypt for securely hashing and verifying user passwords.
bcrypt = Bcrypt(app)

# Authlib for Google OAuth integration.
oauth = OAuth(app)
oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


# --- User model for Flask-Login with SQLAlchemy ---
class User(db.Model, UserMixin):
    """
    Represents a user in the application database.
    Includes fields for local and Google authentication, subscription status,
    Stripe customer IDs, and the generated license code.
    """
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=True)  # Nullable for Google users
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    subscription_status = db.Column(db.String(20), nullable=False, default="Free")
    stripe_customer_id = db.Column(db.String(120), unique=True, nullable=True)
    stripe_subscription_id = db.Column(db.String(120), unique=True, nullable=True)
    license_code = db.Column(db.String(120), unique=True, nullable=True)
    license_expiry_date = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"User('{self.email}', '{self.subscription_status}')"


@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database by ID for Flask-Login."""
    return db.session.get(User, int(user_id))


# --- Routes ---

@app.route("/")
def home():
    """Renders the home page."""
    return render_template("index.html", title="Home")


@app.route("/pricing")
@login_required
def pricing():
    """
    Renders the pricing page, requiring the user to be logged in.
    Passes Stripe keys to the template for client-side use.
    """
    return render_template(
        "pricing.html",
        title="Pricing",
        stripe_publishable_key=STRIPE_PUBLISHABLE_KEY,
        monthly_plan_id=STRIPE_MONTHLY_PLAN_ID,
        annual_plan_id=STRIPE_ANNUAL_PLAN_ID
    )


@app.route("/profile")
@login_required
def profile():
    """
    Renders the user's profile page.
    db.session.refresh(current_user) is a critical line here to ensure the latest
    data is fetched from the database, preventing stale data from being displayed
    after a subscription change.
    """
    db.session.refresh(current_user)
    return render_template("profile.html", title="Profile", user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login with email and password."""
    if current_user.is_authenticated:
        return redirect(url_for("profile"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user and user.password and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for("profile"))
        else:
            flash("Login Unsuccessful. Please check email and password.", "danger")

    return render_template("login.html", title="Login")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Handles user registration with email and password."""
    if current_user.is_authenticated:
        return redirect(url_for("profile"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("This email is already registered.", "warning")
        else:
            user = User(email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash("Your account has been created! You are now able to log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html", title="Register")


@app.route("/logout")
@login_required
def logout():
    """Logs out the current user."""
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.route("/login/google")
def login_google():
    """Initiates the Google OAuth login process."""
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    # A 'nonce' is generated and stored in the session to prevent replay attacks.
    nonce = secrets.token_urlsafe(32)
    session["nonce"] = nonce
    return oauth.google.authorize_redirect(url_for("callback_google", _external=True), nonce=nonce)


@app.route("/callback/google")
def callback_google():
    """
    Handles the callback from Google OAuth.
    It verifies the nonce and handles three cases:
    1. An existing user logs in.
    2. A new user with an existing email links their Google account.
    3. A completely new user is registered.
    """
    try:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token, nonce=session.get("nonce"))
        del session["nonce"]  # Remove the nonce after successful verification

        google_id = user_info["sub"]
        email = user_info["email"]

        user = User.query.filter_by(google_id=google_id).first()

        if user:
            login_user(user)
            flash("Successfully logged in with Google!", "success")
        else:
            existing_user_with_email = User.query.filter_by(email=email).first()

            if existing_user_with_email:
                existing_user_with_email.google_id = google_id
                db.session.commit()
                login_user(existing_user_with_email)
                flash("Your Google account has been linked to your existing account and you have been logged in!",
                      "success")
            else:
                new_user = User(email=email, google_id=google_id)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                flash("Account created and logged in with Google!", "success")

        return redirect(url_for("profile"))

    except Exception as e:
        flash(f"An error occurred during Google sign-in: {e}", "danger")
        return redirect(url_for("login"))


@app.route("/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    """
    Creates a Stripe Checkout Session for a subscription.
    This route handles both new and existing Stripe customers and attaches
    user and price metadata for use in the webhook.
    """
    try:
        price_id = request.form.get("price_id")

        if not current_user.stripe_customer_id:
            customer = stripe.Customer.create(
                email=current_user.email,
            )
            current_user.stripe_customer_id = customer.id
            db.session.commit()

        customer_id = current_user.stripe_customer_id

        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    "price": price_id,
                    "quantity": 1,
                },
            ],
            mode="subscription",
            # Use urljoin to create absolute URLs for success and cancel.
            success_url=urljoin(request.url_root, url_for("success")),
            cancel_url=urljoin(request.url_root, url_for("cancel")),
            # Metadata is crucial for linking Stripe events back to the user in the webhook.
            metadata={"user_id": current_user.id, "price_id": price_id},
            customer=customer_id,
        )
        return jsonify({"id": checkout_session.id})
    except Exception as e:
        print(f"Error creating checkout session: {e}")
        return jsonify(error=str(e)), 403


@app.route("/success")
@login_required
def success():
    """Renders the success page after a successful checkout."""
    flash("Subscription was successful! We're updating your account now.", "success")
    return render_template("success.html", title="Success")


@app.route("/get-subscription-status")
@login_required
def get_subscription_status():
    """
    This is an API endpoint for the front-end to poll for the user's updated subscription status.
    It's used on the success page to provide a seamless user experience.
    """
    db.session.refresh(current_user)  # Ensure the latest data is retrieved from the DB
    return jsonify({"status": current_user.subscription_status})


@app.route("/cancel")
def cancel():
    """Renders the cancel page after a checkout is cancelled."""
    flash("Subscription was cancelled.", "danger")
    return redirect(url_for("pricing"))


@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    """
    Handles Stripe webhook events. This is the core logic for keeping the
    application's database in sync with Stripe subscription changes.
    It handles checkout completion, subscription updates, and cancellations.
    """
    payload = request.get_data()
    sig_header = request.headers.get("stripe-signature")
    event = None

    try:
        # Verifies the webhook signature to ensure the event is from Stripe and not spoofed.
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        print(f"Webhook Error: Invalid payload: {e}")
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        print(f"Webhook Error: Invalid signature: {e}")
        return "Invalid signature", 400

    # Handle the event based on its type
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        user_id = session.get("metadata", {}).get("user_id")
        customer_id = session.get("customer")
        subscription_id = session.get("subscription")
        price_id = session.get("metadata", {}).get("price_id")

        if user_id:
            user = User.query.get(int(user_id))
            if user:
                # Update user's Stripe IDs.
                user.stripe_customer_id = customer_id
                user.stripe_subscription_id = subscription_id

                # Determine the subscription status based on the plan.
                subscription_status = "Free"
                if price_id == STRIPE_MONTHLY_PLAN_ID:
                    subscription_status = "Monthly"
                elif price_id == STRIPE_ANNUAL_PLAN_ID:
                    subscription_status = "Annually"

                user.subscription_status = subscription_status
                db.session.commit()
                print(
                    f"User {user.email} subscription status updated to {user.subscription_status} via checkout session.")

                # New: Send a POST request to the deployed license generator app.
                try:
                    if CODE_GENERATOR_URL:
                        license_type = "annual" if price_id == STRIPE_ANNUAL_PLAN_ID else "monthly"
                        requests.post(
                            urljoin(CODE_GENERATOR_URL, "/generate_code"),
                            json={
                                "license_type": license_type,
                                "user_email": user.email
                            }
                        )
                        print(f"Successfully sent request to code generator for {user.email}.")
                    else:
                        print("CODE_GENERATOR_URL environment variable is not set. Cannot generate license code.")
                except requests.exceptions.RequestException as e:
                    print(f"Failed to send request to code generator: {e}")

    elif event["type"] == "customer.subscription.updated":
        # Handles a change to an existing subscription (e.g., plan change, payment failure).
        subscription_data = event['data']['object']
        customer_id = subscription_data.get('customer')

        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if user:
            subscription_status = "Free"
            if subscription_data['status'] == 'active':
                price_id = subscription_data['items']['data'][0]['price']['id']
                if price_id == STRIPE_MONTHLY_PLAN_ID:
                    subscription_status = "Monthly"
                elif price_id == STRIPE_ANNUAL_PLAN_ID:
                    subscription_status = "Annually"

            user.subscription_status = subscription_status

            # Revoke the license if the subscription is no longer active.
            if subscription_status == "Free":
                user.license_code = None
                user.license_expiry_date = None

            db.session.commit()
            print(f"Subscription for user {user.email} updated to {user.subscription_status}")

    elif event["type"] == "customer.subscription.deleted":
        # Handles a subscription cancellation.
        subscription_data = event['data']['object']
        customer_id = subscription_data.get('customer')

        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if user:
            user.subscription_status = "Free"
            user.license_code = None  # Revoke the license.
            user.license_expiry_date = None
            db.session.commit()
            print(f"Subscription for user {user.email} was deleted. Status set to Free. License revoked.")

    return "", 200


@app.route('/create-customer-portal-session', methods=['POST'])
@login_required
def create_customer_portal_session():
    """
    Creates a Stripe Customer Portal session, allowing users to manage their billing,
    payment methods, and subscriptions directly with Stripe.
    """
    try:
        customer_id = current_user.stripe_customer_id

        if not customer_id:
            customer = stripe.Customer.create(
                email=current_user.email,
            )
            current_user.stripe_customer_id = customer.id
            db.session.commit()
            customer_id = customer.id

        session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=url_for('profile', _external=True)
        )

        return jsonify({'url': session.url})

    except stripe.error.StripeError as e:
        print(f"Error creating customer portal session: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == "__main__":
    with app.app_context():
        # This will create all database tables based on the User model
        # within the application context. This is the correct way to do it
        # with Flask-SQLAlchemy.
        db.create_all()
    # No need to specify a different port. The default is fine for local testing.
    app.run(debug=True)
