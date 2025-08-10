# C:\Users\Administrator\PycharmProjects\app_download_website\app.py
import os
import secrets
import stripe
import json  # Import json for webhook payload parsing
from urllib.parse import urljoin

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

# Load environment variables from the .env file
load_dotenv()

# --- App Initialization and Configuration ---
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")

# Configure the database to use the DATABASE_URL environment variable exclusively
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Stripe configuration
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")
STRIPE_MONTHLY_PLAN_ID = os.environ.get("STRIPE_MONTHLY_PLAN_ID")
STRIPE_ANNUAL_PLAN_ID = os.environ.get("STRIPE_ANNUAL_PLAN_ID")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# Bcrypt for password hashing
bcrypt = Bcrypt(app)

# Authlib for Google OAuth
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
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=True)
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    subscription_status = db.Column(db.String(20), nullable=False, default="Free")
    # New column to store the Stripe Customer ID
    stripe_customer_id = db.Column(db.String(120), unique=True, nullable=True)
    stripe_subscription_id = db.Column(db.String(120), unique=True, nullable=True)

    def __repr__(self):
        return f"User('{self.email}', '{self.subscription_status}')"


@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database by ID."""
    return db.session.get(User, int(user_id))


# --- Routes ---
@app.route("/")
def home():
    return render_template("index.html", title="Home")


@app.route("/pricing")
@login_required
def pricing():
    # Pass all necessary Stripe keys to the pricing template.
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
    # To ensure the latest subscription status is shown, refresh the user object
    db.session.refresh(current_user)
    return render_template("profile.html", title="Profile", user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
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
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.route("/login/google")
def login_google():
    """Initiates the Google OAuth login process with nonce."""
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    # Generate and store a nonce to prevent replay attacks.
    nonce = secrets.token_urlsafe(32)
    session["nonce"] = nonce
    return oauth.google.authorize_redirect(url_for("callback_google", _external=True), nonce=nonce)


@app.route("/callback/google")
def callback_google():
    """Handles the callback from Google OAuth."""
    try:
        # Pass the request to authorize_access_token, which handles nonce verification
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token, nonce=session.get("nonce"))
        # Clear the nonce from the session after use
        del session["nonce"]

        google_id = user_info["sub"]
        email = user_info["email"]

        user = User.query.filter_by(google_id=google_id).first()

        if user:
            login_user(user)
            flash("Successfully logged in with Google!", "success")
        else:
            existing_user_with_email = User.query.filter_by(email=email).first()

            if existing_user_with_email:
                # An account with this email exists, link the Google ID to it.
                existing_user_with_email.google_id = google_id
                db.session.commit()
                login_user(existing_user_with_email)
                flash("Your Google account has been linked to your existing account and you have been logged in!",
                      "success")
            else:
                # New user, register them with their Google ID.
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
    """Creates a Stripe Checkout Session for a subscription."""
    try:
        price_id = request.form.get("price_id")

        # Check if the user already has a Stripe customer ID
        if not current_user.stripe_customer_id:
            # Create a new customer if one does not exist
            customer = stripe.Customer.create(
                email=current_user.email,
            )
            current_user.stripe_customer_id = customer.id
            db.session.commit()  # Save the new customer ID to the database

        customer_id = current_user.stripe_customer_id

        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    "price": price_id,
                    "quantity": 1,
                },
            ],
            mode="subscription",
            success_url=urljoin(request.url_root, url_for("success")),
            cancel_url=urljoin(request.url_root, url_for("cancel")),
            metadata={"user_id": current_user.id},
            customer=customer_id,
        )
        return jsonify({"id": checkout_session.id})
    except Exception as e:
        # Log the error for debugging
        print(f"Error creating checkout session: {e}")
        return jsonify(error=str(e)), 403


@app.route("/success")
@login_required
def success():
    # Render the success page, which will poll for the subscription status update.
    flash("Subscription was successful! We're updating your account now.", "success")
    return render_template("success.html", title="Success")


@app.route("/get-subscription-status")
@login_required
def get_subscription_status():
    """Endpoint for polling the user's subscription status."""
    # This is a critical line to ensure we get the latest data from the database
    db.session.refresh(current_user)
    return jsonify({"status": current_user.subscription_status})


@app.route("/cancel")
def cancel():
    flash("Subscription was cancelled.", "danger")
    return redirect(url_for("pricing"))


@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    """Handles Stripe webhook events to update user subscription status."""
    payload = request.get_data()
    sig_header = request.headers.get("stripe-signature")
    event = None

    try:
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

        if user_id:
            user = User.query.get(int(user_id))
            if user:
                # Update the user's Stripe IDs
                user.stripe_customer_id = customer_id
                user.stripe_subscription_id = subscription_id

                # Get the subscription status from the session and update the user
                if subscription_id:
                    subscription = stripe.Subscription.retrieve(subscription_id)
                    price_id = subscription['items']['data'][0]['price']['id']

                    if price_id == STRIPE_MONTHLY_PLAN_ID:
                        user.subscription_status = "Monthly"
                    elif price_id == STRIPE_ANNUAL_PLAN_ID:
                        user.subscription_status = "Annually"
                    else:
                        user.subscription_status = "Free"

                db.session.commit()
                print(
                    f"User {user.email} subscription status updated to {user.subscription_status} via checkout session.")

    elif event["type"] == "customer.subscription.updated":
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
            else:
                # The subscription is not active, set it to Free
                subscription_status = "Free"

            user.subscription_status = subscription_status
            db.session.commit()
            print(f"Subscription for user {user.email} updated to {user.subscription_status}")

    elif event["type"] == "customer.subscription.deleted":
        subscription_data = event['data']['object']
        customer_id = subscription_data.get('customer')

        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if user:
            user.subscription_status = "Free"
            db.session.commit()
            print(f"Subscription for user {user.email} was deleted. Status set to Free.")

    return "", 200


# New route to create a session for the Stripe Customer Portal
@app.route('/create-customer-portal-session', methods=['POST'])
@login_required
def create_customer_portal_session():
    """Creates a Stripe Customer Portal session for the current user."""
    try:
        customer_id = current_user.stripe_customer_id

        if not customer_id:
            # If for some reason the customer ID is missing, create one.
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
        # This will create all database tables in your Neon PostgreSQL database
        db.create_all()
    app.run(debug=True)
