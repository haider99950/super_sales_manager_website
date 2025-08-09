from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

# Create the SQLAlchemy instance without passing the app
db = SQLAlchemy()

# This is our User model. We will store user data here.
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # password_hash is nullable for users who sign up via OAuth
    password_hash = db.Column(db.String(128), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    is_activated = db.Column(db.Boolean, default=False) # New column for account activation status

    # Store creation and update timestamps
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def set_password(self, password):
        """Hashes the password and sets the password_hash."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.email
