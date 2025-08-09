# db.py

# This file now imports the db instance from the main application file (app.py)
# so we don't have to initialize it multiple times.

from app import db # The change is here! We are importing `db` from app.py
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

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

    def set_password(self, password):
        """Hashes the password and sets the password_hash."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email}>'

