# create_db.py
from app import app, db

with app.app_context():
    # This will drop the existing 'users' table and all its data.
    db.drop_all()
    # This will create a new 'users' table with the correct schema
    # including the new license_code and license_expiry_date columns.
    db.create_all()
    print("Database tables dropped and recreated successfully!")