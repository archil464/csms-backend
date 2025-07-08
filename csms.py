from flask import Flask, request, jsonify, current_app
from flask_restx import Api, Resource, fields
from flask_cors import CORS
import re
import os
from pathlib import Path
import logging
import hashlib
import secrets
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta
import jwt

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost:4200",  # cd Angular dev server
            "https://csms.ugt.ge",   # Production frontend
            "https://www.csms.ugt.ge" # Optional: with www prefix
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "expose_headers": ["Content-Type", "Authorization"]
    }
})

# Database configuration for PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)

db = SQLAlchemy(app)

# Initialize Swagger API
api = Api(
    app,
    version='1.0',
    title='Car Service Management System API',
    description='A simple API for user registration, phone number storage, and admin authentication',
    doc='/docs/'
)

# Define namespaces
users_ns = api.namespace('users', description='User operations')
numbers_ns = api.namespace('numbers', description='Phone number operations')
auth_ns = api.namespace('auth', description='Authentication operations')

# --- SQLAlchemy Models ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    company = db.Column(db.Text)
    email = db.Column(db.Text)
    phone = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP(timezone=True), server_default=db.func.now())

class UsersNumber(db.Model):
    __tablename__ = 'users_numbers'
    id = db.Column(db.Integer, primary_key=True)
    details_number = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.TIMESTAMP(timezone=True), server_default=db.func.now())

class AdminUser(db.Model):
    __tablename__ = 'admin_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    password_hash = db.Column(db.Text, nullable=False)
    salt = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.TIMESTAMP(timezone=True), server_default=db.func.now())

# --- Database Initialization ---
def initialize_database():
    try:
        with app.app_context():
            db.create_all()
            logger.info("✅ PostgreSQL tables ensured to exist.")

            if not AdminUser.query.filter_by(username="admin").first():
                username = "admin"
                password = "SecurePass123!"
                salt = secrets.token_hex(16)
                password_hash = hashlib.sha256((password + salt).encode()).hexdigest()

                new_admin = AdminUser(username=username, password_hash=password_hash, salt=salt)
                db.session.add(new_admin)
                db.session.commit()
                logger.info(f"🔐 Created default admin user: {username}")
            else:
                logger.info("Default admin user 'admin' already exists.")
            
            logger.info("✅ Database initialized successfully!")
            logger.info(f"📍 Database connected to: {app.config['SQLALCHEMY_DATABASE_URI']}")

    except Exception as e:
        logger.error(f"❌ Error initializing database: {e}", exc_info=True)
        raise

initialize_database()

# --- Validation functions ---
def validate_email(email):
    pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    cleaned_phone = re.sub(r'[\s\-\(\)\+]', '', phone)
    return cleaned_phone.isdigit() and len(cleaned_phone) >= 7

# --- API Models for Swagger documentation ---
user_model = api.model('User', {
    'name': fields.String(required=True, description='Full name'),
    'company': fields.String(description='Company name'),
    'email': fields.String(description='Email address'),
    'phone': fields.String(description='Phone number')
})

number_model = api.model('PhoneNumber', {
    'details_number': fields.String(required=True, description='Phone number')
})

login_model = api.model('Login', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password')
})

# --- Authentication Endpoint ---
@auth_ns.route('/login')
class UserLogin(Resource):
    @auth_ns.expect(login_model)
    def post(self):
        """Authenticate admin user and return JWT tokens"""
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            
            if not username or not password:
                return {'error': 'Username and password are required'}, 401
            
            admin_user = AdminUser.query.filter_by(username=username).first()
            
            if not admin_user:
                logger.warning(f"Login attempt for non-existent user: {username}")
                return {'error': 'Invalid credentials'}, 401
                
            stored_hash = admin_user.password_hash
            salt = admin_user.salt
            input_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            if secrets.compare_digest(input_hash, stored_hash):
                # Generate JWT tokens
                access_token = jwt.encode({
                    'sub': admin_user.id,
                    'username': admin_user.username,
                    'exp': datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
                    'iat': datetime.utcnow(),
                    'type': 'access'
                }, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')
                
                refresh_token = jwt.encode({
                    'sub': admin_user.id,
                    'exp': datetime.utcnow() + current_app.config['JWT_REFRESH_TOKEN_EXPIRES'],
                    'iat': datetime.utcnow(),
                    'type': 'refresh'
                }, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')
                
                logger.info(f"Login successful for user: {username}")
                return {
                    'message': 'Login successful',
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'expires_in': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
                }, 200
            else:
                logger.warning(f"Invalid password attempt for user: {username}")
                return {'error': 'Invalid credentials'}, 401
                
        except Exception as e:
            logger.error(f"Login error: {str(e)}", exc_info=True)
            return {'error': 'An unexpected error occurred during login'}, 500

# --- Add token refresh endpoint ---
@auth_ns.route('/refresh')
class TokenRefresh(Resource):
    def post(self):
        """Refresh access token using refresh token"""
        try:
            refresh_token = request.json.get('refresh_token')
            if not refresh_token:
                return {'error': 'Refresh token is required'}, 400
            
            try:
                payload = jwt.decode(
                    refresh_token,
                    current_app.config['JWT_SECRET_KEY'],
                    algorithms=['HS256']
                )
                
                if payload.get('type') != 'refresh':
                    return {'error': 'Invalid token type'}, 401
                
                admin_user = AdminUser.query.get(payload['sub'])
                if not admin_user:
                    return {'error': 'User not found'}, 404
                
                new_access_token = jwt.encode({
                    'sub': admin_user.id,
                    'username': admin_user.username,
                    'exp': datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
                    'iat': datetime.utcnow(),
                    'type': 'access'
                }, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')
                
                return {
                    'access_token': new_access_token,
                    'expires_in': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
                }, 200
                
            except jwt.ExpiredSignatureError:
                return {'error': 'Refresh token has expired'}, 401
            except jwt.InvalidTokenError:
                return {'error': 'Invalid refresh token'}, 401
                
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}", exc_info=True)
            return {'error': 'An unexpected error occurred during token refresh'}, 500

# --- User Registration Endpoint ---
@users_ns.route('/register')
class UserRegistration(Resource):
    @users_ns.expect(user_model)
    def post(self):
        """Register a new user"""
        try:
            data = request.get_json()
            logger.info(f"📥 Received registration data: {data}")
            
            if not data:
                return {'error': 'No data provided'}, 400

            name = data.get('name', '').strip()
            company = data.get('company', '').strip() or None
            email = data.get('email', '').strip() or None
            phone = data.get('phone', '').strip() or None

            # Validation
            if not name:
                return {'error': 'Name is required'}, 400
            
            if not email and not phone:
                return {'error': 'Either email or phone number is required'}, 400
            
            if email and not validate_email(email):
                return {'error': 'Invalid email format'}, 400
            
            if phone and not validate_phone(phone):
                return {'error': 'Invalid phone number format'}, 400

            # Create a new User object and add to session
            new_user = User(name=name, email=email, phone=phone, company=company)
            db.session.add(new_user)
            db.session.commit() # Commit changes to the database
            
            logger.info(f"✅ Successfully registered user with ID: {new_user.id}")
            
            return {
                'message': 'Registration successful!',
                'user_id': new_user.id
            }, 201

        except SQLAlchemyError as e:
            db.session.rollback() # Rollback in case of database error
            logger.error(f"Database error during user registration: {e}", exc_info=True)
            return {'error': 'A database error occurred during registration'}, 500
        except Exception as e:
            logger.error(f"Unexpected error during user registration: {e}", exc_info=True)
            return {'error': 'An unexpected error occurred during registration'}, 500

# --- Phone Number Endpoint ---
@numbers_ns.route('/detail_number')
class PhoneNumber(Resource):
    @numbers_ns.expect(number_model)
    def post(self):
        """Store a phone number"""
        try:
            data = request.get_json()
            logger.info(f"📥 Received phone number data: {data}")
            
            if not data:
                return {'error': 'No data provided'}, 400

            details_number = data.get('details_number', '').strip()
            
            if not details_number:
                return {'error': 'Details number is required'}, 400
            
            if not validate_phone(details_number):
                return {'error': 'Invalid phone number format'}, 400

            # Create a new UsersNumber object and add to session
            new_number = UsersNumber(details_number=details_number)
            db.session.add(new_number)
            db.session.commit()
            
            logger.info(f"✅ Successfully stored phone number with ID: {new_number.id}")
            
            return {
                'message': 'Phone number saved successfully!',
                'number_id': new_number.id
            }, 201

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error saving phone number: {e}", exc_info=True)
            return {'error': 'A database error occurred while saving phone number'}, 500
        except Exception as e:
            logger.error(f"Error saving phone number: {e}", exc_info=True)
            return {'error': 'An unexpected error occurred while saving phone number'}, 500

# --- Get All Users Endpoint ---
@users_ns.route('/all')
class GetAllUsers(Resource):
    def get(self):
        """Get all registered users"""
        try:
            # Query all users, ordered by creation date descending
            users = User.query.order_by(User.created_at.desc()).all()
            
            # Convert SQLAlchemy objects to list of dictionaries for JSON response
            users_data = []
            for user in users:
                users_data.append({
                    'id': user.id,
                    'name': user.name,
                    'company': user.company,
                    'email': user.email,
                    'phone': user.phone,
                    # Convert datetime objects to ISO format string
                    'created_at': user.created_at.isoformat() if user.created_at else None
                })
            
            logger.info(f"📊 Retrieved {len(users_data)} users")
            return users_data

        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving users: {e}", exc_info=True)
            return {'error': 'A database error occurred while retrieving users'}, 500
        except Exception as e:
            logger.error(f"Error retrieving users: {e}", exc_info=True)
            return {'error': 'An unexpected error occurred while retrieving users'}, 500

# --- Get All Phone Numbers Endpoint ---
@numbers_ns.route('/all')
class GetAllNumbers(Resource):
    def get(self):
        """Get all phone numbers"""
        try:
            # Query all phone numbers, ordered by creation date descending
            numbers = UsersNumber.query.order_by(UsersNumber.created_at.desc()).all()
            
            # Convert SQLAlchemy objects to list of dictionaries for JSON response
            numbers_data = []
            for number in numbers:
                numbers_data.append({
                    'id': number.id,
                    'details_number': number.details_number,
                    # Convert datetime objects to ISO format string
                    'created_at': number.created_at.isoformat() if number.created_at else None
                })
            
            logger.info(f"📊 Retrieved {len(numbers_data)} phone numbers")
            return numbers_data

        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving phone numbers: {e}", exc_info=True)
            return {'error': 'A database error occurred while retrieving phone numbers'}, 500
        except Exception as e:
            logger.error(f"Error retrieving phone numbers: {e}", exc_info=True)
            return {'error': 'An unexpected error occurred while retrieving phone numbers'}, 500

# --- Delete specific user endpoint ---
@users_ns.route('/delete/<int:user_id>')
class DeleteUser(Resource):
    def delete(self, user_id):
        """Delete a specific user"""
        try:
            # Find user by ID
            user = User.query.get(user_id)

            if not user:
                return {'error': 'User not found'}, 404
            
            db.session.delete(user) # Mark for deletion
            db.session.commit()     # Commit the deletion
            
            logger.info(f"🗑️ Deleted user with ID: {user_id}")
            return {'message': 'User deleted successfully'}, 200

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error deleting user: {e}", exc_info=True)
            return {'error': 'A database error occurred while deleting user'}, 500
        except Exception as e:
            logger.error(f"Error deleting user: {e}", exc_info=True)
            return {'error': 'An unexpected error occurred while deleting user'}, 500

# --- Delete specific number endpoint ---
@numbers_ns.route('/delete/<int:number_id>')
class DeleteNumber(Resource):
    def delete(self, number_id):
        """Delete a specific phone number"""
        try:
            # Find number by ID
            number = UsersNumber.query.get(number_id)

            if not number:
                return {'error': 'Number not found'}, 404
            
            db.session.delete(number)
            db.session.commit()
            
            logger.info(f"🗑️ Deleted number with ID: {number_id}")
            return {'message': 'Number deleted successfully'}, 200

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error deleting number: {e}", exc_info=True)
            return {'error': 'A database error occurred while deleting phone number'}, 500
        except Exception as e:
            logger.error(f"Error deleting number: {e}", exc_info=True)
            return {'error': 'An unexpected error occurred while deleting phone number'}, 500

# --- Health Check Endpoint ---
@api.route('/health')
class HealthCheck(Resource):
    def get(self):
        """Check API and database status"""
        try:
            # Test database connection by performing a simple count query
            user_count = User.query.count()
            number_count = UsersNumber.query.count()
            
            return {
                'status': '✅ OK',
                'message': 'API is running smoothly!',
                'database': {
                    'connection_string': app.config['SQLALCHEMY_DATABASE_URI'], # Show connection string
                    'connected': True,
                    'users_count': user_count,
                    'numbers_count': number_count
                },
                'endpoints': {
                    'api_docs': '/docs/',
                    'register_user': '/users/register',
                    'save_number': '/numbers/detail_number',
                    'get_users': '/users/all',
                    'get_numbers': '/numbers/all',
                    'login': '/auth/login'
                }
            }, 200

        except SQLAlchemyError as e:
            logger.error(f"Health check database error: {e}", exc_info=True)
            return {
                'status': '❌ ERROR',
                'message': 'Database connection failed or query error',
                'error': str(e)
            }, 500
        except Exception as e:
            logger.error(f"Health check failed: {e}", exc_info=True)
            return {
                'status': '❌ ERROR',
                'message': 'An unexpected error occurred during health check',
                'error': str(e)
            }, 500

# --- Delete all users endpoint ---
@users_ns.route('/delete_all')
class DeleteAllUsers(Resource):
    def delete(self):
        """Delete all users"""
        try:
            # Delete all records from the User table
            deleted_count = db.session.query(User).delete()
            db.session.commit()
            
            logger.info(f"🗑️ Deleted all {deleted_count} users")
            return {'message': f'Deleted all {deleted_count} users successfully'}, 200

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error deleting all users: {e}", exc_info=True)
            return {'error': 'A database error occurred while deleting all users'}, 500
        except Exception as e:
            logger.error(f"Error deleting all users: {e}", exc_info=True)
            return {'error': 'An unexpected error occurred while deleting all users'}, 500

# --- Delete all phone numbers endpoint ---
@numbers_ns.route('/delete_all')
class DeleteAllNumbers(Resource):
    def delete(self):
        """Delete all phone numbers"""
        try:
            # Delete all records from the UsersNumber table
            deleted_count = db.session.query(UsersNumber).delete()
            db.session.commit()
            
            logger.info(f"🗑️ Deleted all {deleted_count} phone numbers")
            return {'message': f'Deleted all {deleted_count} phone numbers successfully'}, 200

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error deleting all phone numbers: {e}", exc_info=True)
            return {'error': 'A database error occurred while deleting all phone numbers'}, 500
        except Exception as e:
            logger.error(f"Error deleting all phone numbers: {e}", exc_info=True)
            return {'error': 'An unexpected error occurred while deleting all phone numbers'}, 500

# --- Welcome Endpoint ---
@api.route('/welcome')
class Welcome(Resource):
    def get(self):
        """Welcome message"""
        return {
            'message': 'Welcome to Car Service Management System API',
            'documentation': '/docs/',
            'health': '/health',
            'status': 'running'
        }

# --- Main entry point for running the Flask app ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    if not app.config['SQLALCHEMY_DATABASE_URI']:
        logger.warning("SQLALCHEMY_DATABASE_URI not set! Running with default settings.")
    
    app.run(host='0.0.0.0', port=port)
