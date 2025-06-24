from flask import Flask, request, jsonify
from flask_restx import Api, Resource, fields
from flask_cors import CORS
import sqlite3
import re
import os
from pathlib import Path
import logging
import hashlib
import secrets

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database path - Use Railway's persistent volume or local path
# Railway provides persistent storage at /app/data
if os.path.exists('/app'):
    # Railway environment
    DB_PATH = Path('/app/data/users.db')
    os.makedirs('/app/data', exist_ok=True)
else:
    # Local development
    DB_PATH = Path('data/users.db')
    os.makedirs('data', exist_ok=True)

print(f"Database will be created at: {DB_PATH.absolute()}")

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize Swagger API
api = Api(
    app,
    version='1.0',
    title='Car Service Management System API',
    description='A simple API for user registration and phone number storage',
    doc='/docs/'  # Changed from /swagger/ to /docs/
)

# Define namespaces
users_ns = api.namespace('users', description='User operations')
numbers_ns = api.namespace('numbers', description='Phone number operations')
auth_ns = api.namespace('auth', description='Authentication operations')

# Database initialization
def init_db():
    try:
        # Ensure parent directory exists
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                company TEXT,
                email TEXT,
                phone TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CHECK (email IS NOT NULL OR phone IS NOT NULL)
            )
        ''')
        
        # Create phone numbers table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users_numbers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                details_number TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create admin users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Add a default admin user if none exists
        cursor.execute("SELECT COUNT(*) FROM admin_users")
        if cursor.fetchone()[0] == 0:
            # Create a secure default admin
            username = "admin"
            password = "SecurePass123!"
            salt = secrets.token_hex(16)
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            cursor.execute(
                "INSERT INTO admin_users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt)
            )
            logger.info(f"🔐 Created default admin user: {username}")
        
        conn.commit()
        logger.info("✅ Database initialized successfully!")
        logger.info(f"📍 Database located at: {DB_PATH.absolute()}")
        
    except Exception as e:
        logger.error(f"❌ Error initializing database: {e}")
        raise
    finally:
        if 'conn' in locals():
            conn.close()

# Initialize database when app starts
init_db()

# Validation functions
def validate_email(email):
    pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    cleaned_phone = re.sub(r'[\s\-\(\)\+]', '', phone)
    return cleaned_phone.isdigit() and len(cleaned_phone) >= 7

# API Models for Swagger documentation
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

# Authentication endpoint
@auth_ns.route('/login')
class UserLogin(Resource):
    @auth_ns.expect(login_model)
    def post(self):
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            
            logger.info(f"Login attempt for username: {username}")
            
            if not username or not password:
                return {'error': 'Username and password are required'}, 401
            
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_hash, salt FROM admin_users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            
            if not result:
                logger.warning(f"No user found with username: {username}")
                return {'error': 'Invalid credentials'}, 401
                
            stored_hash, salt = result
            logger.info(f"Stored hash: {stored_hash}")
            logger.info(f"Salt: {salt}")
            
            # Log what we're about to hash
            logger.info(f"Hashing input: password='{password}' + salt='{salt}'")
            
            input_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            logger.info(f"Computed hash: {input_hash}")
            
            if secrets.compare_digest(input_hash, stored_hash):
                token = secrets.token_hex(32)
                logger.info("Login successful")
                return {
                    'message': 'Login successful',
                    'token': token
                }, 200
            else:
                logger.warning("Password hash mismatch")
                return {'error': 'Invalid credentials'}, 401
                
        except Exception as e:
            logger.error(f"Login error: {e}", exc_info=True)
            return {'error': 'An unexpected error occurred'}, 500
        finally:
            if conn:
                conn.close()

# User Registration Endpoint
@users_ns.route('/register')
class UserRegistration(Resource):
    @users_ns.expect(user_model)
    def post(self):
        """Register a new user"""
        conn = None
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

            # Database operation
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (name, email, phone, company) VALUES (?, ?, ?, ?)",
                (name, email, phone, company)
            )
            user_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f"✅ Successfully registered user with ID: {user_id}")
            
            return {
                'message': 'Registration successful!',
                'user_id': user_id
            }, 201

        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return {'error': 'An unexpected error occurred'}, 500
        finally:
            if conn:
                conn.close()

# Phone Number Endpoint
@numbers_ns.route('/detail_number')
class PhoneNumber(Resource):
    @numbers_ns.expect(number_model)
    def post(self):
        """Store a phone number"""
        conn = None
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

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users_numbers (details_number) VALUES (?)",
                (details_number,)
            )
            number_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f"✅ Successfully stored phone number with ID: {number_id}")
            
            return {
                'message': 'Phone number saved successfully!',
                'number_id': number_id
            }, 201

        except Exception as e:
            logger.error(f"Error saving phone number: {e}")
            return {'error': 'An unexpected error occurred'}, 500
        finally:
            if conn:
                conn.close()

# Get All Users Endpoint
@users_ns.route('/all')
class GetAllUsers(Resource):
    def get(self):
        """Get all registered users"""
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
            rows = cursor.fetchall()
            
            # Convert to list of dictionaries
            columns = [description[0] for description in cursor.description]
            users = [dict(zip(columns, row)) for row in rows]
            
            logger.info(f"📊 Retrieved {len(users)} users")
            return users

        except Exception as e:
            logger.error(f"Error retrieving users: {e}")
            return {'error': str(e)}, 500
        finally:
            if conn:
                conn.close()

# Get All Phone Numbers Endpoint
@numbers_ns.route('/all')
class GetAllNumbers(Resource):
    def get(self):
        """Get all phone numbers"""
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users_numbers ORDER BY created_at DESC")
            rows = cursor.fetchall()
            
            # Convert to list of dictionaries
            columns = [description[0] for description in cursor.description]
            numbers = [dict(zip(columns, row)) for row in rows]
            
            logger.info(f"📊 Retrieved {len(numbers)} phone numbers")
            return numbers

        except Exception as e:
            logger.error(f"Error retrieving phone numbers: {e}")
            return {'error': str(e)}, 500
        finally:
            if conn:
                conn.close()

# Delete specific user
@users_ns.route('/delete/<int:user_id>')
class DeleteUser(Resource):
    def delete(self, user_id):
        """Delete a specific user"""
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
            if not cursor.fetchone():
                return {'error': 'User not found'}, 404
            
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            
            logger.info(f"🗑️ Deleted user with ID: {user_id}")
            return {'message': 'User deleted successfully'}, 200

        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            return {'error': str(e)}, 500
        finally:
            if conn:
                conn.close()

# Delete specific number
@numbers_ns.route('/delete/<int:number_id>')
class DeleteNumber(Resource):
    def delete(self, number_id):
        """Delete a specific phone number"""
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Check if number exists
            cursor.execute("SELECT id FROM users_numbers WHERE id = ?", (number_id,))
            if not cursor.fetchone():
                return {'error': 'Number not found'}, 404
            
            cursor.execute("DELETE FROM users_numbers WHERE id = ?", (number_id,))
            conn.commit()
            
            logger.info(f"🗑️ Deleted number with ID: {number_id}")
            return {'message': 'Number deleted successfully'}, 200

        except Exception as e:
            logger.error(f"Error deleting number: {e}")
            return {'error': str(e)}, 500
        finally:
            if conn:
                conn.close()

# Health Check Endpoint
@api.route('/health')
class HealthCheck(Resource):
    def get(self):
        """Check API and database status"""
        try:
            # Test database connection
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM users_numbers")
            number_count = cursor.fetchone()[0]
            conn.close()
            
            return {
                'status': '✅ OK',
                'message': 'API is running smoothly!',
                'database': {
                    'path': str(DB_PATH.absolute()),
                    'exists': DB_PATH.exists(),
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

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                'status': '❌ ERROR',
                'message': 'Database connection failed',
                'error': str(e)
            }, 500
# Delete all users endpoint
@users_ns.route('/delete_all')
class DeleteAllUsers(Resource):
    def delete(self):
        """Delete all users"""
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM users")
            deleted_count = cursor.rowcount
            conn.commit()
            
            logger.info(f"🗑️ Deleted all {deleted_count} users")
            return {'message': f'Deleted all {deleted_count} users successfully'}, 200

        except Exception as e:
            logger.error(f"Error deleting all users: {e}")
            return {'error': str(e)}, 500
        finally:
            if conn:
                conn.close()

# Delete all phone numbers endpoint
@numbers_ns.route('/delete_all')
class DeleteAllNumbers(Resource):
    def delete(self):
        """Delete all phone numbers"""
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM users_numbers")
            deleted_count = cursor.rowcount
            conn.commit()
            
            logger.info(f"🗑️ Deleted all {deleted_count} phone numbers")
            return {'message': f'Deleted all {deleted_count} phone numbers successfully'}, 200

        except Exception as e:
            logger.error(f"Error deleting all phone numbers: {e}")
            return {'error': str(e)}, 500
        finally:
            if conn:
                conn.close()

@api.route('/debug_db')
class DebugDB(Resource):
    def get(self):
        db_exists = os.path.exists(DB_PATH)
        return {
            'db_path': str(DB_PATH),
            'exists': db_exists,
            'size': os.path.getsize(DB_PATH) if db_exists else 0
        }, 200
# Root endpoint - using Flask route instead of api.route
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
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)