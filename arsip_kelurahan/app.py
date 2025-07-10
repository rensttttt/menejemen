

# Standard library imports
import os
import re
import secrets
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps
import mimetypes
import json
import uuid
import traceback
# Third-party imports
import pytz
import bleach
import mysql.connector
from mysql.connector import Error, errorcode
from flask_login import current_user
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, session, send_from_directory, current_app as app
)
from flask_login import (
    LoginManager, login_user, logout_user,
    current_user, login_required, UserMixin
)
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import generate_csrf
from wtforms import (
    StringField, PasswordField, BooleanField, SelectField,
    TextAreaField, FileField, SubmitField
)
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo, Regexp, Optional
)
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from wtforms import StringField, TextAreaField, SelectField, BooleanField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from functools import wraps
from flask import redirect, url_for, flash
from flask import current_app
from dateutil.parser import parse
from flask_wtf.csrf import validate_csrf
from flask import request
import json
from decimal import Decimal
from flask import jsonify
from flask_wtf.csrf import CSRFError
from wtforms import Form, StringField, PasswordField, validators
from mysql.connector import Error as MySQL_Error
from flask import jsonify
import string
from wtforms import Form, StringField, BooleanField, HiddenField, validators
from flask import send_file
# Initialize Flask app
app = Flask(__name__)
logger = logging.getLogger(__name__)
app.config.from_pyfile('config.py')
app.config['SECRET_KEY'] = os.environ.get('sadadsadewefdsfsdcdsfewfedwY', secrets.token_hex(16))
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_FILE_SIZE'] = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
csrf = CSRFProtect(app)



# Setup logger
os.makedirs('logs', exist_ok=True)
logger = logging.getLogger('arsip_kelurahan')
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('logs/arsip_kelurahan.log', maxBytes=1000000, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize Flask-Mail
mail = Mail(app)

# Database Configuration
db_config = {

    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'arsip2',
    'raise_on_warnings': True,
    'charset': 'utf8mb4'
}





def get_admin_user_id():
    # Contoh sederhana mengambil user admin dari database
    conn = get_db_connection()
    admin_id = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
        result = cursor.fetchone()
        if result:
            admin_id = result[0]
    except Exception as e:
        logger.error(f"Error getting admin user id: {e}", exc_info=True)
    finally:
        cursor.close()
        if conn.is_connected():
            conn.close()
    return admin_id


def create_notification(user_id, title, message, type, related_id):
    # Fungsi insert notifikasi ke database
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        insert_sql = """
            INSERT INTO notifications (user_id, title, message, type, related_id, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
        """
        cursor.execute(insert_sql, (user_id, title, message, type, related_id))
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to create notification: {e}", exc_info=True)
    finally:
        cursor.close()
        if conn.is_connected():
            conn.close()

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


class ArchiveForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=255), validators.DataRequired()])
    user_id = SelectField('User', [validators.DataRequired()], coerce=int)
    category = StringField('Category', [validators.Length(min=0, max=100)])
    description = TextAreaField('Description', [validators.Length(min=0, max=500)])
    file = FileField('File')
    is_public = BooleanField('Is Public')

# Fungsi untuk membersihkan file yang gagal diunggah
def cleanup_uploaded_file(file_info):
    try:
        file_path = file_info.get('file_path')
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
            logger.debug(f"Cleaned up file: {file_path}")
    except Exception as e:
        logger.error(f"Failed to clean up file {file_path}: {e}")


def has_permission(user_id, permission):
    conn = get_db_connection()
    if not conn:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT is_allowed FROM user_permissions WHERE user_id = %s AND permission = %s",
            (user_id, permission)
        )
        result = cursor.fetchone()
        return result and result[0] == 1
    except Error as e:
        logger.error(f"Permission check error: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()



# Helper Functions
def get_db_connection():
    """Create and return a new database connection."""
    try:
        connection = mysql.connector.connect(**db_config)
        if connection.is_connected():
            return connection
    except Error as e:
        logger.error(f"Database connection failed: {e}")
        log_system_error("Database", f"Connection failed: {e}")
    return None

def generate_secure_password(length=12):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password)
           and any(c.isupper() for c in password)
           and any(c.isdigit() for c in password)
           and any(c in "!@#$%^&*" for c in password)):
            return password


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_file_extension(filename):
    """Get the file extension from the filename."""
    return filename.rsplit('.', 1)[1].lower() if '.' in filename else None

def generate_unique_filename(filename):
    """Generate a unique filename by appending a timestamp to the original filename."""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    name, ext = os.path.splitext(filename)


def seed_categories():
    """
    Seed the categories table with predefined categories.
    """
    categories = [
        'Surat Keterangan',
        'Surat Kelahiran',
        'Surat Kematian',
        'Surat Dinas',
        'Surat Permohonan',
        'Surat Undangan',
        'Surat Edaran',
        'Surat Keputusan',
        'Surat Pengantar'
    ]

    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error("Gagal menghubungkan ke database saat seeding categories")
            return

        cursor = conn.cursor()

        # Check if categories already exist to avoid duplicates
        cursor.execute("SELECT name FROM categories")
        existing_categories = [row[0] for row in cursor.fetchall()]

        # Insert only new categories
        for category in categories:
            if category not in existing_categories:
                cursor.execute(
                    "INSERT INTO categories (name) VALUES (%s)",
                    (category,)
                )
                logger.info(f"Kategori '{category}' berhasil ditambahkan")
            else:
                logger.info(f"Kategori '{category}' sudah ada, dilewati")

        conn.commit()
        logger.info("Seeding categories selesai")

    except mysql.connector.Error as e:
        logger.error(f"Error saat seeding categories: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()
        logger.debug("Koneksi database ditutup")

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Anda harus login untuk mengakses halaman ini', 'warning')
                return redirect(url_for('login', next=request.url))  # ← ganti di sini

            if current_user.is_superadmin:
                return f(*args, **kwargs)

            try:
                conn = get_db_connection()
                with conn.cursor(dictionary=True) as cursor:
                    # Cek 1: Izin langsung ke user
                    cursor.execute("""
                        SELECT is_allowed FROM user_permissions 
                        WHERE user_id = %s AND permission = %s
                    """, (current_user.id, permission))
                    perm = cursor.fetchone()

                    # Cek 2: Izin dari role
                    if not perm:
                        cursor.execute("""
                            SELECT rp.is_allowed FROM user_roles ur
                            JOIN role_permissions rp ON ur.role_id = rp.role_id
                            WHERE ur.user_id = %s AND rp.permission = %s
                        """, (current_user.id, permission))
                        perm = cursor.fetchone()

                    if not perm or not perm.get('is_allowed'):
                        flash(f'Anda tidak memiliki izin "{permission}"', 'danger')
                        logger.warning(f"Permission denied for {current_user.username} - {permission}")
                        return redirect(url_for('dashboard'))

                    return f(*args, **kwargs)

            except mysql.connector.Error as err:
                logger.error(f"Database error: {err}")
                flash('Terjadi kesalahan saat memverifikasi izin', 'danger')
                return redirect(url_for('dashboard'))

            finally:
                if conn and conn.is_connected():
                    conn.close()

        return decorated_function
    return decorator

def is_valid_uuid(uuid_str):
    """Validate if a string is a valid UUID."""
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False

def check_upload_permission(user_id):
    try:
        conn = get_db_connection()
        with conn.cursor(dictionary=True) as cursor:
            # Cek permission langsung
            cursor.execute("""
                SELECT is_allowed FROM user_permissions 
                WHERE user_id = %s AND permission = 'archive_upload'
            """, (user_id,))
            direct_perm = cursor.fetchone()
            
            if direct_perm and direct_perm['is_allowed']:
                return True
                
            # Cek permission dari role
            cursor.execute("""
                SELECT rp.is_allowed 
                FROM user_roles ur
                JOIN role_permissions rp ON ur.role_id = rp.role_id
                WHERE ur.user_id = %s AND rp.permission = 'archive_upload'
            """, (user_id,))
            role_perm = cursor.fetchone()
            
            return role_perm and role_perm['is_allowed']
    except Exception as e:
        logger.error(f"Permission check error: {e}")
        return False
    finally:
        if conn and conn.is_connected():
            conn.close()

@login_manager.unauthorized_handler
def unauthorized():
    if request.blueprint == 'api':
        return jsonify({'error': 'Unauthorized'}), 401
    flash('Anda harus login untuk mengakses halaman ini', 'warning')
    return redirect(url_for('login', next=request.url))

def validate_email(email):
    """Validate email format."""
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password):
    """Validate password strength."""
    if not password or len(password) < 8:
        return False
    return (
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password) and
        any(c in '!@#$%^&*()' for c in password)
    )

def validate_username(username):
    """Validate username format."""
    if not username or len(username) < 4 or len(username) > 80:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_]+$', username))

def admin_required(f):
    """Decorator to restrict access to admin or superadmin users."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not (current_user.is_admin or current_user.is_superadmin):
            flash('You do not have permission to access this page.', 'danger')
            log_activity(
                user_id=current_user.id if current_user.is_authenticated else None,
                action='access_denied',
                ip_address=request.remote_addr or 'unknown',
                user_agent=request.user_agent.string or 'unknown',
                description=f"Attempted access to {request.path}"
            )
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename, allowed_extensions=None):
    """
    Check if the file has an allowed extension.

    :param filename: str, nama file
    :param allowed_extensions: set atau list ekstensi yang diizinkan (misal {'pdf', 'docx', 'jpg'})
                               jika None, akan menggunakan nilai default dari konfigurasi aplikasi
    :return: bool, True jika ekstensi diperbolehkan, False jika tidak
    """
    if not filename or '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    
    if allowed_extensions is None:
        # Pastikan ini adalah set ekstensi yang diizinkan dari konfigurasi aplikasi (app.config)
        # Misal app.config['ALLOWED_EXTENSIONS'] sudah didefinisikan di file konfigurasi Flask Anda
        allowed_extensions = app.config.get('ALLOWED_EXTENSIONS', {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'})
    
    return ext in allowed_extensions


# log helper
def log_security_event(event: str):
    with open("security.log", "a") as log_file:
        log_file.write(f"[SECURITY] {event}\n")

# setting helper
def get_system_setting(key: str):
    # contoh hardcoded, bisa kamu ganti akses ke file json/config lain
    settings = {
        "maintenance_mode": False,
        "max_login_attempts": 5
    }
    return settings.get(key, None)




def get_user_notifications(user_id):
    """
    Ambil notifikasi untuk user tertentu dari database.
    Return list notifikasi dalam bentuk dict.
    """
    notifications = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = "SELECT id, message, is_read, created_at FROM notifications WHERE user_id = %s ORDER BY created_at DESC"
        cursor.execute(query, (user_id,))
        notifications = cursor.fetchall()
        cursor.close()
        conn.close()
    except Exception as e:
        app.logger.error(f"Failed to get notifications for user {user_id}: {str(e)}")
    return notifications



# Fungsi untuk mencatat aktivitas pengguna
def log_activity(user_id, action, ip_address, user_agent, description, details=None):
    """Log user activity to database"""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if conn and conn.is_connected():
            cursor = conn.cursor()
            
            # Pastikan query dan parameter sesuai
            query = """
                INSERT INTO user_logs 
                (user_id, action, ip_address, user_agent, description, details, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            
            # Serialize details jika berupa dictionary
            details_str = json.dumps(details) if details and isinstance(details, (dict, list)) else str(details) if details else None
            
            # Eksekusi query dengan parameter yang sesuai
            cursor.execute(query, (
                user_id,
                action,
                ip_address,
                user_agent,
                description,
                details_str,
                datetime.now(pytz.timezone('Asia/Jakarta'))  # Gunakan timestamp yang konsisten
            ))
            
            conn.commit()
    except Exception as e:  # Tangkap semua exception, bukan hanya Error
        logging.error(f"Log activity failed - User: {user_id}, Action: {action}, Error: {str(e)}", 
                     exc_info=True)
        # Jangan re-raise exception agar tidak mengganggu alur utama
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# Fungsi untuk mencatat log sistem
def log_system_error(module, message, ip_address=None, user_id=None, details=None):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if conn and conn.is_connected():
            cursor = conn.cursor()
            query = """
                INSERT INTO system_logs (level, module, message, ip_address, user_id, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
            """
            cursor.execute(query, ('ERROR', module, message, ip_address or 'unknown', user_id, str(details) if details else None))
            conn.commit()
    except Error as e:
        logging.error(f"Log system error failed: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()



@app.context_processor
def inject_current_year():
    """Inject current year into templates."""
    return {'current_year': datetime.now(pytz.timezone('Asia/Jakarta')).year}


def get_archive_stats(cursor, user_id=None):
    """
    Mengambil statistik arsip:
    - total_archives: jumlah seluruh arsip
    - incoming_letters: jumlah surat masuk (letter_type = 'in')
    - outgoing_letters: jumlah surat keluar (letter_type = 'out')
    - category_count: jumlah kategori arsip
    """
    stats = {
        'total_archives': 0,
        'incoming_letters': 0,
        'outgoing_letters': 0,
        'category_count': 0
    }

    cursor.execute("SELECT COUNT(*) AS total FROM archives")
    stats['total_archives'] = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) AS total FROM archives WHERE letter_type = 'in'")
    stats['incoming_letters'] = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) AS total FROM archives WHERE letter_type = 'out'")
    stats['outgoing_letters'] = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) AS total FROM archive_categories")
    stats['category_count'] = cursor.fetchone()['total']

    return stats


# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=4, max=80, message='Username must be between 4 and 80 characters'),
        Regexp('^[a-zA-Z0-9_]+$', message='Username must contain only letters, numbers, or underscores')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address'),
        Length(max=120, message='Email must be less than 120 characters')
    ])
    full_name = StringField('Full Name', validators=[
        DataRequired(message='Full name is required'),
        Length(min=2, max=255, message='Full name must be between 2 and 255 characters')
    ])
    phone = StringField('Phone Number', validators=[
        Optional(),
        Length(max=15, message='Phone number must be at most 15 characters'),
        Regexp('^[0-9+]*$', message='Phone number must contain only digits or +')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=8, max=255, message='Password must be between 8 and 255 characters'),
        EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password')
    ])
    submit = SubmitField('Register')

class ArchiveUploadForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=255)])
    description = TextAreaField('Description', validators=[Length(max=65535)])
    category = SelectField('Category', choices=[
        ('document', 'Document'),
        ('image', 'Image'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    file = FileField('File', validators=[DataRequired()])
    is_public = BooleanField('Make Public')
    submit = SubmitField('Upload')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=80),
        Regexp('^[a-zA-Z0-9_]+$', message='Username must contain only letters, numbers, or underscores')
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(),
        Length(max=120)
    ])
    full_name = StringField('Full Name', validators=[
        DataRequired(),
        Length(min=2, max=255)
    ])
    phone = StringField('Phone', validators=[
        Optional(),
        Length(max=15),
        Regexp('^[0-9+]*$', message='Phone number must contain only digits or +')
    ])
    submit = SubmitField('Update Profile')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    submit = SubmitField('Request Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, max=255),
        EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')


class AdminUserForm(Form):
    user_id = HiddenField('User ID')  # Tambahkan ini untuk menghindari error Jinja2
    username = StringField('Username', [
        validators.Length(min=4, max=80),
        validators.DataRequired()
    ])
    email = StringField('Email', [
        validators.Email(),
        validators.DataRequired()
    ])
    full_name = StringField('Full Name', [
        validators.Length(min=1, max=255),
        validators.DataRequired()
    ])
    phone = StringField('Phone', [
        validators.Length(min=0, max=20),
        validators.Optional()
    ])
    is_admin = BooleanField('Is Admin')
    is_superadmin = BooleanField('Is Superadmin')
    is_active = BooleanField('Is Active')

class ArchiveForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=255), validators.DataRequired()])
    user_id = SelectField('User', [validators.DataRequired()], coerce=int)
    category = StringField('Category', [validators.Length(min=0, max=100)])
    tags = StringField('Tags', [validators.Length(min=0, max=255)])
    description = TextAreaField('Description', [validators.Length(min=0, max=500)])
    file = FileField('File')
    is_public = BooleanField('Is Public')
    


    email = StringField('Email', validators=[
        DataRequired(),
        Email(),
        Length(max=120)
    ])
    full_name = StringField('Full Name', validators=[
        DataRequired(),
        Length(min=2, max=255)
    ])
    is_admin = BooleanField('Admin')
    is_superadmin = BooleanField('Superadmin')
    submit = SubmitField('Save User')

class SettingsForm(FlaskForm):
    key = StringField('Key', validators=[DataRequired(), Length(max=100)])
    value = TextAreaField('Value', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Length(max=65535)])
    submit = SubmitField('Save Setting')


def format_file_size(size):
    """Convert bytes to human-readable format."""
    if size is None:
        return "0.00 B"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, is_admin, is_superadmin, full_name, phone):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin
        self.is_superadmin = is_superadmin
        self.full_name = full_name
        self.phone = phone

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)


# Register strftime filter for Jinja2
def strftime(value, format='%d %b %Y %H:%M'):
    """Jinja2 filter to format datetime objects or return a default string"""
    if value is None or isinstance(value, str):
        return value or 'N/A'
    return value.strftime(format)

app.jinja_env.filters['strftime'] = strftime


def get_last_login(user_id):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()  # Pastikan fungsi ini sudah ada dan koneksi ke DB
        cursor = conn.cursor()
        query = "SELECT last_login FROM user WHERE id = %s"
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        if result and result[0]:
            return result[0]
        else:
            return None
    except Exception as e:
        # Log error sesuai kebutuhan
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.template_filter('datetimeformat')
def datetimeformat(value, format='%d %B %Y, %H:%M'):
    """Format datetime object to string."""
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value
    return value.strftime(format)



@login_manager.user_loader
def load_user(user_id):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if not conn:
            app.logger.error("Failed to load user: Database connection failed")
            return None

        cursor = conn.cursor(dictionary=True)

        try:
            user_id_int = int(user_id)
        except ValueError:
            app.logger.error(f"Invalid user_id: {user_id}")
            return None

        cursor.execute(
            """
            SELECT id, username, email, full_name, phone, is_admin, is_superadmin 
            FROM user 
            WHERE id = %s AND is_active = TRUE
            """,
            (user_id_int,)
        )
        user_data = cursor.fetchone()
        if user_data:
            return User(
                id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                is_admin=bool(user_data['is_admin']),
                is_superadmin=bool(user_data['is_superadmin']),
                full_name=user_data['full_name'],
                phone=user_data['phone']
            )
        else:
            app.logger.info(f"User not found or inactive for id: {user_id}")
            return None

    except Exception as e:
        app.logger.error(f"User load error: {e}")
        return None

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):  # Huruf besar
        return False
    if not re.search(r'[a-z]', password):  # Huruf kecil
        return False
    if not re.search(r'[0-9]', password):  # Angka
        return False
    if not re.search(r'[\W_]', password):  # Karakter spesial
        return False
    return True


# Helper function for input sanitization
def sanitize_input(input_str):
    """
    Sanitize input string to prevent injection attacks.
    
    Args:
        input_str (str): Input string to sanitize
    
    Returns:
        str: Sanitized string or None if input is invalid
    """
    if not input_str:
        return None
    # Remove dangerous characters and limit length
    sanitized = re.sub(r'[^\w\s-]', '', input_str.strip())[:50]
    return sanitized if sanitized else None


def get_recent_activities(cursor, user_id):
    """Get recent activities for the given user."""
    cursor.execute("""
        SELECT 
            id,
            action AS title,
            COALESCE(details, action) AS description,
            action AS type,
            created_at AS timestamp,
            COALESCE(
                CASE 
                    WHEN archive_id IS NOT NULL THEN CONCAT('/archives/', archive_id)
                    WHEN user_id IS NOT NULL THEN CONCAT('/users/', user_id)
                    ELSE NULL
                END, 
                '#'
            ) AS link
        FROM user_logs
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 5
    """, (user_id,))
    
    activities = cursor.fetchall() or []
    
    # Format timestamps
    for activity in activities:
        if activity.get('timestamp'):
            activity['timestamp'] = activity['timestamp'].isoformat()
    
    return activities


def get_chart_data(cursor, user_id):
    """Get archive data for chart (last 6 months)."""
    cursor.execute("""
        SELECT 
            DATE_FORMAT(created_at, '%%b %%Y') AS month,
            DATE_FORMAT(created_at, '%%Y-%%m') AS month_key,
            COUNT(*) AS count
        FROM archives
        WHERE user_id = %s
          AND created_at >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
        GROUP BY month_key
        ORDER BY month_key
    """, (user_id,))
    
    chart_rows = cursor.fetchall() or []
    
    return {
        'labels': [row['month'] for row in chart_rows],
        'data': [row['count'] for row in chart_rows]
    }


def get_mysql_error_message(error):
    """Get user-friendly message for MySQL errors."""
    error_messages = {
        errorcode.CR_CONNECTION_ERROR: "Database connection error",
        errorcode.CR_CONN_HOST_ERROR: "Database host error",
        errorcode.ER_ACCESS_DENIED_ERROR: "Database access denied",
        errorcode.ER_BAD_DB_ERROR: "Database not found",
        errorcode.ER_DBACCESS_DENIED_ERROR: "Database access denied",
        errorcode.ER_NO_SUCH_TABLE: "Database table not found"
    }
    
    return error_messages.get(getattr(error, 'errno', None), "Database operation failed")





# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/favicon.ico')
def favicon():
    return '', 204


@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    """
    Route untuk login user.
    Melakukan autentikasi, manajemen sesi, serta logging aktivitas.
    """
    # Jika user sudah login, redirect berdasarkan peran
    if current_user.is_authenticated:
        if current_user.is_admin or current_user.is_superadmin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))

    form = LoginForm()

    if request.method == 'POST':
        # Validasi form
        if not form.validate_on_submit():
            flash('Form submission invalid. Periksa kembali semua field.', 'danger')
            return render_template('auth/login.html', form=form, title='Login')

        # Sanitasi input
        username = sanitize_input(form.username.data.strip())
        password = form.password.data
        ip_address = request.remote_addr or 'unknown'
        user_agent = request.user_agent.string or 'unknown'

        conn = None
        cursor = None

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                flash('Gagal koneksi ke database. Silakan coba lagi nanti.', 'danger')
                logger.error("Database connection failed during login attempt")
                log_system_error(
                    module="Authentication",
                    message="Database connection failed during login attempt",
                    ip_address=ip_address,
                    user_id=None
                )
                return render_template('auth/login.html', form=form, title='Login')

            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT id, username, email, password, is_admin, is_superadmin,
                       full_name, phone, is_active, login_attempts
                FROM user WHERE username = %s
                """,
                (username,)
            )
            user = cursor.fetchone()

            if not user:
                flash('Username atau password salah.', 'danger')
                logger.warning(f"Login attempt for non-existent user: {username}")
                log_activity(
                    user_id=None,
                    action='failed_login',
                    ip_address=ip_address,
                    user_agent=user_agent,
                    description=f"Failed login attempt for non-existent user: {username}"
                )
                return render_template('auth/login.html', form=form, title='Login')

            if not user['is_active']:
                flash('Akun Anda dinonaktifkan. Hubungi administrator.', 'danger')
                logger.warning(f"Login attempt for inactive account: {username}")
                log_activity(
                    user_id=user['id'],
                    action='failed_login',
                    ip_address=ip_address,
                    user_agent=user_agent,
                    description=f"Login attempt for inactive account: {username}"
                )
                return render_template('auth/login.html', form=form, title='Login')

            if user['login_attempts'] >= 5:
                flash('Terlalu banyak percobaan gagal. Akun terkunci sementara.', 'danger')
                logger.warning(f"Account locked due to too many failed attempts: {username}")
                log_activity(
                    user_id=user['id'],
                    action='failed_login',
                    ip_address=ip_address,
                    user_agent=user_agent,
                    description=f"Account locked due to too many failed attempts: {username}"
                )
                return render_template('auth/login.html', form=form, title='Login')

            if not check_password_hash(user['password'], password):
                # Update login attempts
                cursor.execute(
                    "UPDATE user SET login_attempts = login_attempts + 1 WHERE id = %s",
                    (user['id'],)
                )
                conn.commit()
                flash('Username atau password salah.', 'danger')
                logger.warning(f"Failed login attempt: {username}")
                log_activity(
                    user_id=user['id'],
                    action='failed_login',
                    ip_address=ip_address,
                    user_agent=user_agent,
                    description=f"Failed login attempt: {username}"
                )
                return render_template('auth/login.html', form=form, title='Login')

            # Autentikasi berhasil, buat objek user
            user_obj = User(
                id=user['id'],
                username=user['username'],
                email=user['email'],
                is_admin=bool(user['is_admin']),
                is_superadmin=bool(user['is_superadmin']),
                full_name=user['full_name'],
                phone=user.get('phone')
            )

            login_user(user_obj, remember=form.remember.data)

            # Reset login attempts dan update waktu login terakhir
            jakarta_time = datetime.now(pytz.timezone('Asia/Jakarta'))
            cursor.execute(
                """
                UPDATE user SET last_login = %s, login_attempts = 0 WHERE id = %s
                """,
                (jakarta_time, user['id'])
            )
            conn.commit()

            # Log aktivitas login berhasil
            log_activity(
                user_id=user['id'],
                action='login',
                ip_address=ip_address,
                user_agent=user_agent,
                description=f"Successful login for {username}",
                details={'is_admin': user['is_admin'], 'is_superadmin': user['is_superadmin']}
            )

            flash('Login berhasil!', 'success')

            # Tentukan redirect berdasarkan peran
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):  # Validasi URL aman
                return redirect(next_page)
            if user['is_admin'] or user['is_superadmin']:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))

        except mysql.connector.Error as e:
            logger.error(f"Login MySQL error: {e}", exc_info=True)
            log_system_error(
                module="Authentication",
                message=f"MySQL error during login: {str(e)}",
                ip_address=ip_address,
                user_id=None
            )
            flash(f'Terjadi kesalahan database. Silakan coba lagi nanti.', 'danger')
            return render_template('auth/login.html', form=form, title='Login')

        except Exception as e:
            logger.error(f"Login unexpected error: {e}", exc_info=True)
            log_system_error(
                module="Authentication",
                message=f"Unexpected error during login: {str(e)}",
                ip_address=ip_address,
                user_id=None
            )
            flash(f'Terjadi kesalahan sistem. Silakan coba lagi nanti.', 'danger')
            return render_template('auth/login.html', form=form, title='Login')

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # Untuk method GET, tampilkan halaman login
    return render_template('auth/login.html', form=form, title='Login')

def is_safe_url(target):
    """Validasi URL untuk mencegah redirect berbahaya."""
    from urllib.parse import urlparse, urljoin
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc



@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.email.data
        # TODO: proses reset password, misal cek email di DB, kirim email reset link, dll
        flash('Link reset password telah dikirim ke email Anda.', 'success')
        return redirect(url_for('login'))  # ganti 'login' sesuai route login Anda

    # Jika GET request atau validasi gagal, render template dengan form
    return render_template('auth/forgot_password.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegisterForm()

    if form.validate_on_submit():
        # Bersihkan input
        username = sanitize_input(form.username.data.strip())
        email = sanitize_input(form.email.data.strip().lower())
        password = form.password.data
        full_name = sanitize_input(form.full_name.data.strip())
        phone = sanitize_input(form.phone.data.strip()) if form.phone.data else None

        # Proses registrasi
        conn = None
        cursor = None

        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                flash('Koneksi database gagal.', 'danger')
                return render_template('auth/register.html', form=form, title='Register')

            cursor = conn.cursor(dictionary=True)

            # Cek jika username/email sudah terdaftar
            cursor.execute(
                "SELECT id FROM user WHERE username = %s OR email = %s",
                (username, email)
            )
            if cursor.fetchone():
                flash('Username atau email sudah digunakan.', 'danger')
                return render_template('auth/register.html', form=form, title='Register')

            # Hash password
            password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

            # Timestamp dengan zona waktu Jakarta
            created_at = datetime.now(pytz.timezone('Asia/Jakarta'))

            # Masukkan user baru ke DB
            cursor.execute("""
                INSERT INTO user 
                (username, email, password, full_name, phone, created_at, is_active, email_verified)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                username, email, password_hash, full_name, phone,
                created_at, True, False
            ))

            user_id = cursor.lastrowid
            conn.commit()

            # Log aktivitas
            log_activity(
                user_id=user_id,
                action='register',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                description=f"User {username} berhasil registrasi"
            )

            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))

        except Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Error registrasi: {e}")
            log_system_error("Auth", f"Registration error: {e}")
            flash('Terjadi kesalahan saat registrasi. Coba lagi nanti.', 'danger')

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # Tampilkan pesan error validasi form
    for field, errors in form.errors.items():
        for error in errors:
            flash(error, 'danger')

    return render_template('auth/register.html', form=form, title='Register')



@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """
    Handle password reset using a valid token.
    Validates token expiry and password strength.
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = ResetPasswordForm()
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed. Please try again later.', 'danger')
            return redirect(url_for('forgot_password'))

        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, username 
            FROM user 
            WHERE reset_token = %s AND reset_token_expiry > %s AND is_active = TRUE
        """, (token, datetime.now(pytz.timezone('Asia/Jakarta'))))
        user = cursor.fetchone()

        if not user:
            flash('Invalid or expired reset token.', 'danger')
            return redirect(url_for('forgot_password'))

        if form.validate_on_submit():
            password = form.password.data
            if not validate_password(password):
                flash('Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.', 'danger')
                return render_template('auth/reset_password.html', form=form, token=token, title='Reset Password')

            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            cursor.execute("""
                UPDATE user 
                SET password = %s, reset_token = NULL, reset_token_expiry = NULL 
                WHERE id = %s
            """, (hashed_password, user['id']))
            conn.commit()

            log_activity(
                user_id=user['id'],
                action='password_reset',
                ip_address=request.remote_addr or 'unknown',
                user_agent=request.user_agent.string or 'unknown',
                description=f"User {user['username']} reset their password"
            )

            flash('Your password has been successfully reset. Please login.', 'success')
            return redirect(url_for('login'))

        return render_template('auth/reset_password.html', form=form, token=token, title='Reset Password')

    except Exception as e:
        logger.error(f"Password reset error: {e}", exc_info=True)
        log_system_error("Authentication", f"Password reset exception: {e}")
        flash('An error occurred while processing your request. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route('/logout')
@login_required
def logout():
    """
    Logs out the current user and records the activity.
    """
    user_id = current_user.id
    username = current_user.username

    # Logout user session
    logout_user()

    # Log activity after logout
    log_activity(
        user_id=user_id,
        action='logout',
        ip_address=request.remote_addr or 'unknown',
        user_agent=request.user_agent.string or 'unknown',
        description=f"User {username} logged out."
    )

    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """
    Halaman utama dashboard pengguna.
    - Mencatat aktivitas akses pengguna.
    - Menyediakan data dashboard, termasuk aktivitas terkini dan statistik.
    - Menangani dan mencatat error jika terjadi.
    """
    error_id = str(uuid.uuid4())
    conn = None
    cursor = None
    
    try:
        # Detail akses pengguna
        access_details = {
            'route': request.path,
            'method': request.method,
            'referrer': request.referrer or 'unknown'
        }

        # Logging aktivitas akses dashboard
        log_activity(
            user_id=current_user.id,
            action='dashboard_access',
            ip_address=request.remote_addr or 'unknown',
            user_agent=request.user_agent.string or 'unknown',
            description=f"Akses dashboard oleh {current_user.username}",
            details=access_details
        )

        # Koneksi ke database
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            flash('Gagal terhubung ke database.', 'danger')
            logger.error(f"[{error_id}] Dashboard: Database connection failed")
            log_system_error(
                module="Dashboard",
                message=f"Database connection failed [{error_id}]",
                ip_address=request.remote_addr or 'unknown',
                user_id=current_user.id,
                details={'route': request.path}
            )
            return redirect(url_for('index'))

        cursor = conn.cursor(dictionary=True)

        # Ambil statistik arsip
        stats = get_archive_stats(cursor, current_user.id)
        stats = {k: float(v) if isinstance(v, Decimal) else v for k, v in stats.items()}

        # Ambil aktivitas terkini
        activities = get_recent_activities(cursor, current_user.id)
        for activity in activities:
            if activity.get('created_at'):
                activity['timestamp'] = activity['created_at'].strftime('%d %B %Y, %H:%M')
            if activity.get('details'):
                try:
                    details = json.loads(activity['details'])
                    activity['description'] = format_activity_details(details, activity['action'])
                except json.JSONDecodeError:
                    activity['description'] = 'Detail tidak valid'
            else:
                activity['description'] = activity.get('description', 'Tidak ada deskripsi')

        # Ambil data grafik
        chart_data = get_chart_data(cursor, current_user.id)

        # Persiapan data dashboard
        dashboard_data = {
            'user': current_user,
            'title': 'Dashboard',
            'csrf_token': generate_csrf(),
            'last_login': get_last_login(current_user.id),
            'notifications': get_user_notifications(current_user.id),
            'stats': stats,
            'recent_activities': activities,
            'chart_data': chart_data,
            'current_year': datetime.now(pytz.timezone('Asia/Jakarta')).year
        }

        return render_template('dashboard.html', **dashboard_data)

    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] Dashboard MySQL error: {e}", exc_info=True)
        log_system_error(
            module="Dashboard",
            message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=request.remote_addr or 'unknown',
            user_id=current_user.id,
            details={
                'error_type': type(e).__name__,
                'error_code': getattr(e, 'errno', None),
                'sql_state': getattr(e, 'sqlstate', None),
                'route': request.path
            }
        )
        flash(f'Terjadi kesalahan database (ID: {error_id}). Silakan coba lagi.', 'danger')
        return redirect(url_for('index'))

    except Exception as e:
        logger.error(f"[{error_id}] Dashboard unexpected error: {e}", exc_info=True)
        log_system_error(
            module="Dashboard",
            message=f"Unexpected error [{error_id}]: {str(e)}",
            ip_address=request.remote_addr or 'unknown',
            user_id=current_user.id,
            details={
                'error_type': type(e).__name__,
                'traceback': traceback.format_exc(),
                'route': request.path
            }
        )
        flash(f'Terjadi kesalahan sistem (ID: {error_id}). Silakan coba lagi.', 'danger')
        return redirect(url_for('index'))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/dashboard', methods=['GET'])
@login_required
def api_dashboard():
    """
    API endpoint untuk mendapatkan statistik dashboard pengguna.
    Meliputi: total arsip, surat masuk, surat keluar, kategori unik,
    log aktivitas terakhir, dan data grafik arsip 6 bulan terakhir.
    
    Returns:
        JSON response dengan struktur:
        {
            "status": "success"/"error",
            "stats": {
                "total_archives": int,
                "incoming_letters": int,
                "outgoing_letters": int,
                "category_count": int
            },
            "activities": [list of activity objects],
            "chart_data": {
                "labels": [list of month names],
                "incoming": [list of incoming letter counts],
                "outgoing": [list of outgoing letter counts]
            },
            "error": string (only when status is "error")
        }
    """
    conn = None
    cursor = None
    error_id = str(uuid.uuid4())
    user_ip = request.remote_addr or 'unknown'
    user_agent = request.user_agent.string or 'unknown'

    try:
        # Koneksi ke database
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error(f"[{error_id}] API Dashboard: Database connection failed")
            raise RuntimeError("Database connection failed")

        cursor = conn.cursor(dictionary=True)

        # Ambil statistik arsip
        stats = get_archive_stats(cursor, current_user.id)
        stats = {k: float(v) if isinstance(v, Decimal) else v for k, v in stats.items()}

        # Ambil aktivitas terkini
        activities = get_recent_activities(cursor, current_user.id)
        for activity in activities:
            if activity.get('created_at'):
                activity['timestamp'] = activity['created_at'].strftime('%d %B %Y, %H:%M')
            if activity.get('details'):
                try:
                    details = json.loads(activity['details'])
                    activity['description'] = format_activity_details(details, activity['action'])
                except json.JSONDecodeError:
                    activity['description'] = 'Detail tidak valid'
            else:
                activity['description'] = activity.get('description', 'Tidak ada deskripsi')

        # Ambil data grafik
        chart_data = get_chart_data(cursor, current_user.id)

        # Log akses sukses
        log_activity(
            user_id=current_user.id,
            action='api_dashboard',
            ip_address=user_ip,
            user_agent=user_agent,
            description=f"Pengguna {current_user.username} mengambil data dashboard",
            details={
                'stats': stats,
                'activity_count': len(activities),
                'chart_points': len(chart_data['labels'])
            }
        )

        return jsonify({
            'status': 'success',
            'stats': stats,
            'activities': activities,
            'chart_data': chart_data
        })

    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] API Dashboard MySQL error: {e}", exc_info=True)
        log_system_error(
            module="API Dashboard",
            message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=user_ip,
            user_id=current_user.id,
            details={
                'error_type': type(e).__name__,
                'error_code': getattr(e, 'errno', None),
                'sql_state': getattr(e, 'sqlstate', None)
            }
        )
        return jsonify({
            'status': 'error',
            'error': 'Gagal mengambil data dari database',
            'error_id': error_id
        }), 500

    except Exception as e:
        logger.error(f"[{error_id}] API Dashboard unexpected error: {e}", exc_info=True)
        log_system_error(
            module="API Dashboard",
            message=f"Unexpected error [{error_id}]: {str(e)}",
            ip_address=user_ip,
            user_id=current_user.id,
            details={
                'error_type': type(e).__name__,
                'traceback': traceback.format_exc()
            }
        )
        return jsonify({
            'status': 'error',
            'error': 'Terjadi kesalahan sistem',
            'error_id': error_id
        }), 500

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()



@app.route('/activity', methods=['GET'])
@login_required
def activity():
    """
    Display a paginated list of user activities with filtering.
    
    Args:
        page (int): Page number (default: 1)
        action_filter (str): Filter by activity type (e.g., login, view_archive_list)
    
    Returns:
        Rendered activity.html template with activity logs
    """
    page = request.args.get('page', default=1, type=int)
    action_filter = request.args.get('action_filter', default=None, type=str)
    per_page = 10
    offset = max(0, (page - 1) * per_page)
    error_id = str(uuid.uuid4())

    # Validate page
    if page < 1:
        flash('Nomor halaman tidak valid.', 'danger')
        return redirect(url_for('activity'))

    # Valid actions for filtering
    valid_actions = [
        'login', 'logout', 'upload', 'download', 'delete', 'view', 'archive_delete',
        'profile_update', 'password_change', 'view_activity', 'view_archive_list',
        'view_dashboard'
    ]

    # Validate action_filter
    if action_filter and action_filter not in valid_actions:
        flash('Filter aktivitas tidak valid.', 'danger')
        logger.warning(f"Invalid action filter attempted: {action_filter}")
        return redirect(url_for('activity'))

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            flash('Gagal terhubung ke database.', 'danger')
            logger.error(f"[{error_id}] Activity route: Database connection failed")
            log_system_error(
                module="Activity",
                error_message=f"Database connection failed [{error_id}]",
                ip_address=request.remote_addr or 'unknown',
                user_id=current_user.id,
                details={'route': request.path, 'action_filter': action_filter}
            )
            return redirect(url_for('dashboard'))

        cursor = conn.cursor(dictionary=True)

        # Build query
        where_clause = "WHERE ul.user_id = %s"
        params = [current_user.id]
        if action_filter:
            where_clause += " AND ul.action = %s"
            params.append(action_filter)

        # Count total activities
        count_query = f"""
            SELECT COUNT(*) AS total
            FROM user_logs ul
            {where_clause}
        """
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()['total']
        total_pages = max(1, (total_count + per_page - 1) // per_page)

        if page > total_pages:
            flash('Halaman tidak ditemukan.', 'danger')
            return redirect(url_for('activity', page=total_pages, action_filter=action_filter))

        # Fetch activities
        query = f"""
            SELECT 
                ul.id,
                ul.action,
                ul.description,
                ul.ip_address,
                ul.user_agent,
                ul.created_at,
                ul.details,
                a.title AS archive_title
            FROM user_logs ul
            LEFT JOIN archive_access_log aal 
                ON ul.action IN ('download', 'delete', 'view')
                AND aal.user_id = ul.user_id
                AND aal.access_type = ul.action
                AND ABS(TIMESTAMPDIFF(MICROSECOND, aal.access_time, ul.created_at)) < 1000000
            LEFT JOIN archives a ON aal.archive_id = a.id
            {where_clause}
            ORDER BY ul.created_at DESC
            LIMIT %s OFFSET %s
        """
        params.extend([per_page, offset])
        cursor.execute(query, params)
        activities = cursor.fetchall()

        # Format activities
        for activity in activities:
            if activity.get('created_at'):
                activity['created_at'] = activity['created_at'].strftime('%d %B %Y, %H:%M')

            # Parse and format details
            if activity.get('details'):
                try:
                    details = json.loads(activity['details'])
                    activity['details'] = format_activity_details(details, activity['action'])
                except json.JSONDecodeError:
                    activity['details'] = 'Detail tidak dapat dibaca'
            else:
                activity['details'] = 'Tidak ada detail tambahan'

            activity['archive_title'] = activity['archive_title'] or '-'

        # Log activity
        log_activity(
            user_id=current_user.id,
            action='view_activity',
            ip_address=request.remote_addr or 'unknown',
            user_agent=request.user_agent.string or 'unknown',
            description=f"Pengguna {current_user.username} melihat log aktivitas halaman {page} dengan filter {action_filter or 'semua'}",
            details={
                'page': page,
                'total_activities': total_count,
                'per_page': per_page,
                'action_filter': action_filter
            }
        )

        return render_template(
            'activity.html',
            title='Riwayat Aktivitas',
            activities=activities,
            current_page=page,
            total_pages=total_pages,
            action_filter=action_filter,
            valid_actions=valid_actions,
            csrf_token=generate_csrf(),
            user=current_user
        )

    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] Activity route MySQL error: {e}", exc_info=True)
        log_system_error(
            module="Activity",
            error_message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=request.remote_addr or 'unknown',
            user_id=current_user.id,
            details={
                'error_type': type(e).__name__,
                'error_code': getattr(e, 'errno', None),
                'sql_state': getattr(e, 'sqlstate', None),
                'route': request.path,
                'action_filter': action_filter
            }
        )
        flash(f'Terjadi kesalahan database (ID: {error_id}). Silakan coba lagi.', 'danger')
        return redirect(url_for('dashboard'))

    except Exception as e:
        logger.error(f"[{error_id}] Activity route unexpected error: {e}", exc_info=True)
        log_system_error(
            module="Activity",
            error_message=f"Unexpected error [{error_id}]: {str(e)}",
            ip_address=request.remote_addr or 'unknown',
            user_id=current_user.id,
            details={
                'error_type': type(e).__name__,
                'route': request.path,
                'action_filter': action_filter
            }
        )
        flash(f'Terjadi kesalahan sistem (ID: {error_id}). Silakan coba lagi.', 'danger')
        return redirect(url_for('dashboard'))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

def get_archive_stats(cursor, user_id):
    """Mengambil statistik arsip untuk pengguna tertentu."""
    cursor.execute("""
        SELECT 
            COUNT(*) AS total_archives,
            SUM(CASE WHEN letter_type = 'in' THEN 1 ELSE 0 END) AS incoming_letters,
            SUM(CASE WHEN letter_type = 'out' THEN 1 ELSE 0 END) AS outgoing_letters,
            COUNT(DISTINCT category_id) AS category_count
        FROM archives a
        LEFT JOIN archive_category ac ON a.id = ac.archive_id
        WHERE a.user_id = %s
    """, (user_id,))
    
    result = cursor.fetchone()
    return {
        'total_archives': result['total_archives'] if result else 0,
        'incoming_letters': result['incoming_letters'] if result else 0,
        'outgoing_letters': result['outgoing_letters'] if result else 0,
        'category_count': result['category_count'] if result else 0
    }

def get_chart_data(cursor, user_id):
    """Mengambil data untuk grafik arsip 6 bulan terakhir."""
    cursor.execute("""
        SELECT 
            DATE_FORMAT(created_at, '%Y-%m') AS month,
            SUM(CASE WHEN letter_type = 'in' THEN 1 ELSE 0 END) AS incoming,
            SUM(CASE WHEN letter_type = 'out' THEN 1 ELSE 0 END) AS outgoing
        FROM archives
        WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
        AND user_id = %s
        GROUP BY DATE_FORMAT(created_at, '%Y-%m')
        ORDER BY month DESC
    """, (user_id,))
    
    results = cursor.fetchall()
    labels = []
    incoming_data = []
    outgoing_data = []
    
    # Buat daftar bulan untuk 6 bulan terakhir
    from datetime import datetime, timedelta
    from dateutil.relativedelta import relativedelta
    current_date = datetime.now(pytz.timezone('Asia/Jakarta'))
    for i in range(5, -1, -1):
        month_date = current_date - relativedelta(months=i)
        month_str = month_date.strftime('%Y-%m')
        labels.append(month_date.strftime('%B %Y'))
        
        # Cari data untuk bulan ini
        month_data = next((r for r in results if r['month'] == month_str), None)
        incoming_data.append(month_data['incoming'] if month_data else 0)
        outgoing_data.append(month_data['outgoing'] if month_data else 0)
    
    return {
        'labels': labels,
        'data': {
            'incoming': incoming_data,
            'outgoing': outgoing_data
        }
    }


def format_activity_details(details, action):
    """
    Format JSON details into a human-readable string based on the action type.
    
    Args:
        details (dict): JSON-parsed details from user_logs
        action (str): Action type (e.g., view_activity, view_archive_list)
    
    Returns:
        str: Formatted details string
    """
    try:
        if action == 'view_activity':
            return (f"Melihat halaman {details.get('page', 'tidak diketahui')} "
                    f"dengan filter {details.get('action_filter', 'semua')} "
                    f"(total: {details.get('total_activities', 0)} aktivitas)")
        elif action == 'view_archive_list':
            sort_map = {
                'newest': 'terbaru',
                'oldest': 'terlama',
                'title_asc': 'A-Z',
                'title_desc': 'Z-A'
            }
            return (f"Melihat daftar arsip halaman {details.get('page', 'tidak diketahui')} "
                    f"dengan urutan {sort_map.get(details.get('sort', ''), 'tidak diketahui')} "
                    f"dan filter: query='{details.get('query', '')}', "
                    f"kategori={details.get('category_id', 'semua')}, "
                    f"jenis={details.get('letter_type', 'semua')}, "
                    f"rentang={details.get('date_range', 'semua')} "
                    f"(total: {details.get('total_count', 0)} arsip)")
        elif action == 'view_dashboard':
            return (f"Mengakses dashboard dari {details.get('route', 'tidak diketahui')} "
                    f"dengan referrer {details.get('referrer', 'tidak ada')}")
        elif action == 'archive_delete':
            return (f"Menghapus arsip ID {details.get('archive_id', 'tidak diketahui')} "
                    f"dengan nama file {details.get('file_name', 'tidak diketahui')}")
        elif action in ('login', 'logout'):
            return f"Aksi {action} dari IP {details.get('ip_address', 'tidak diketahui')}"
        else:
            # Generic formatting for other actions
            items = [f"{k}: {v}" for k, v in details.items()]
            return ", ".join(items) if items else "Tidak ada detail spesifik"
    except Exception as e:
        logger.warning(f"Error formatting activity details: {e}")
        return "Detail tidak dapat diformat"


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()

    if request.method == 'GET':
        # Pre-populate form with user data
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.full_name.data = current_user.full_name
        form.phone.data = current_user.phone

    elif form.validate_on_submit():
        # Sanitize inputs
        username = sanitize_input(form.username.data.strip())
        email = sanitize_input(form.email.data.strip().lower())
        full_name = sanitize_input(form.full_name.data.strip())
        phone = sanitize_input(form.phone.data.strip()) if form.phone.data else None

        # Validasi format email
        if not validate_email(email):
            flash('Format email tidak valid.', 'danger')
            return render_template('profile.html', form=form, title='Profil')

        # Validasi format username
        if not validate_username(username):
            flash('Username harus 4–80 karakter dan hanya mengandung huruf, angka, atau underscore (_).', 'danger')
            return render_template('profile.html', form=form, title='Profil')

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                flash('Koneksi ke database gagal.', 'danger')
                return render_template('profile.html', form=form, title='Profil')

            cursor = conn.cursor(dictionary=True)

            # Cek duplikasi username/email selain milik sendiri
            cursor.execute("""
                SELECT id FROM user
                WHERE (username = %s OR email = %s) AND id != %s
            """, (username, email, current_user.id))

            if cursor.fetchone():
                flash('Username atau email sudah digunakan oleh pengguna lain.', 'danger')
                return render_template('profile.html', form=form, title='Profil')

            # Update data pengguna
            cursor.execute("""
                UPDATE user
                SET username = %s,
                    email = %s,
                    full_name = %s,
                    phone = %s,
                    updated_at = %s
                WHERE id = %s
            """, (
                username,
                email,
                full_name,
                phone,
                datetime.now(pytz.timezone('Asia/Jakarta')),
                current_user.id
            ))

            conn.commit()

            # Update session Flask-Login
            current_user.username = username
            current_user.email = email
            current_user.full_name = full_name
            current_user.phone = phone

            # Catat aktivitas
            log_activity(
                user_id=current_user.id,
                action='profile_update',
                ip_address=request.remote_addr or 'unknown',
                user_agent=request.user_agent.string or 'unknown',
                description=f"User {username} updated profile."
            )

            flash('Profil berhasil diperbarui.', 'success')
            return redirect(url_for('profile'))

        except mysql.connector.Error as db_error:
            if conn:
                conn.rollback()
            logger.error(f"MySQL Error saat update profil: {db_error}", exc_info=True)
            log_system_error("Update Profil", f"MySQL error: {db_error}")
            flash('Kesalahan database saat menyimpan profil.', 'danger')
        except Exception as e:
            logger.error(f"Unexpected error saat update profil: {e}", exc_info=True)
            log_system_error("Update Profil", f"Unexpected error: {e}")
            flash('Terjadi kesalahan tidak terduga.', 'danger')
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    return render_template('profile.html', form=form, title='Profil')



@app.route('/api/profile', methods=['GET'])
@login_required
def api_profile():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            return jsonify({'error': 'Koneksi ke database gagal'}), 500

        cursor = conn.cursor(dictionary=True)

        # Ambil data user (hanya kolom yang ada di tabel `user`)
        cursor.execute("""
            SELECT
                id,
                username,
                email,
                full_name,
                phone,
                is_admin,
                is_superadmin,
                is_active,
                email_verified,
                last_login,
                created_at
            FROM `user`
            WHERE id = %s
        """, (current_user.id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'Pengguna tidak ditemukan'}), 404

        # Pecah full_name jadi first_name & last_name
        full_name = user['full_name'] or ''
        parts = full_name.split(' ', 1)
        first_name = parts[0]
        last_name = parts[1] if len(parts) > 1 else ''

        # Hitung statistik arsip
        cursor.execute("SELECT COUNT(*) AS count FROM archives WHERE user_id = %s", (current_user.id,))
        archive_count = cursor.fetchone()['count'] or 0

        # Hitung komentar (gunakan nama tabel yang benar—`comment` bukan `comments`)
        cursor.execute("SELECT COUNT(*) AS count FROM comment WHERE user_id = %s", (current_user.id,))
        comment_count = cursor.fetchone()['count'] or 0

        # Hitung aktivitas bulan ini
        start_of_month = datetime.now(pytz.timezone('Asia/Jakarta')).replace(day=1)
        cursor.execute(
            "SELECT COUNT(*) AS count FROM activity_log WHERE user_id = %s AND created_at >= %s",
            (current_user.id, start_of_month)
        )
        activity_count = cursor.fetchone()['count'] or 0

        # Ambil 5 aktivitas terakhir
        cursor.execute("""
            SELECT action, description, created_at
            FROM activity_log
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 5
        """, (current_user.id,))
        recent_activities = cursor.fetchall()

        # Ambil sesi aktif
        cursor.execute("""
            SELECT id, device, ip_address, location, last_active
            FROM user_session
            WHERE user_id = %s
            ORDER BY last_active DESC
        """, (current_user.id,))
        sessions = cursor.fetchall()
        active_sessions = len(sessions)

        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'full_name': user['full_name'],
            'first_name': first_name,
            'last_name': last_name,
            'phone': user['phone'],
            'is_admin': bool(user['is_admin']),
            'is_superadmin': bool(user['is_superadmin']),
            'is_active': bool(user['is_active']),
            'email_verified': bool(user['email_verified']),
            'last_login': user['last_login'].isoformat() if user['last_login'] else None,
            'created_at': user['created_at'].isoformat(),
            'stats': {
                'archives': archive_count,
                'comments': comment_count,
                'activities': activity_count
            },
            'recent_activities': [
                {
                    'action': act['action'],
                    'description': act['description'],
                    'created_at': act['created_at'].isoformat()
                } for act in recent_activities
            ],
            'sessions': [
                {
                    'id': s['id'],
                    'device': s['device'],
                    'ip_address': s['ip_address'],
                    'location': s['location'],
                    'last_active': s['last_active'].isoformat()
                } for s in sessions
            ],
            'active_sessions': active_sessions
        })

    except Error as e:
        logger.error(f"API profile MySQL error: {e}", exc_info=True)
        log_system_error("API Profile", f"MySQL error: {e}")
        return jsonify({'error': 'Terjadi kesalahan pada database'}), 500

    except Exception as e:
        logger.error(f"API profile unexpected error: {e}", exc_info=True)
        log_system_error("API Profile", f"Unexpected error: {e}")
        return jsonify({'error': 'Terjadi kesalahan tak terduga'}), 500

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route('/api/profile/avatar', methods=['POST'])
@login_required
def api_profile_avatar():
    if 'avatarInput' not in request.files:
        return jsonify({'error': 'Tidak ada file yang diunggah'}), 400

    file = request.files['avatarInput']
    if file.filename == '':
        return jsonify({'error': 'Nama file kosong'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': 'Format file tidak didukung'}), 400

    conn = None
    cursor = None
    try:
        # Simpan file ke folder statis
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(f"{current_user.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{ext}")
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)

        # Update kolom avatar_url (pastikan kolom ini sudah ada jika dipakai)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE `user` SET avatar_url = %s WHERE id = %s",
            (url_for('static', filename=f"uploads/{filename}"), current_user.id)
        )
        conn.commit()

        log_activity(
            user_id=current_user.id,
            action='avatar_update',
            ip_address=request.remote_addr or 'unknown',
            user_agent=request.user_agent.string or 'unknown',
            description=f"User {current_user.username} updated avatar"
        )

        return jsonify({'message': 'Avatar berhasil diperbarui'}), 200

    except Error as e:
        logger.error(f"Avatar upload MySQL error: {e}", exc_info=True)
        log_system_error("Avatar Upload", f"MySQL error: {e}")
        return jsonify({'error': 'Terjadi kesalahan pada database'}), 500

    except Exception as e:
        logger.error(f"Avatar upload unexpected error: {e}", exc_info=True)
        log_system_error("Avatar Upload", f"Unexpected error: {e}")
        return jsonify({'error': 'Terjadi kesalahan tak terduga'}), 500

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()





@app.route('/api/session/<int:session_id>', methods=['DELETE'])
@login_required
def api_session_delete(session_id):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            return jsonify({'error': 'Koneksi ke database gagal'}), 500

        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_session WHERE id = %s AND user_id = %s", (session_id, current_user.id))
        if cursor.rowcount == 0:
            return jsonify({'error': 'Sesi tidak ditemukan atau tidak diizinkan'}), 404

        conn.commit()

        log_activity(
            user_id=current_user.id,
            action='session_logout',
            ip_address=request.remote_addr or 'unknown',
            user_agent=request.user_agent.string or 'unknown',
            description=f"User {current_user.username} logged out session {session_id}"
        )

        return jsonify({'message': 'Sesi berhasil diakhiri'})

    except Error as e:
        conn.rollback()
        logger.error(f"Session delete MySQL error: {e}", exc_info=True)
        log_system_error("Session Delete", f"MySQL error: {e}")
        return jsonify({'error': 'Terjadi kesalahan pada database'}), 500
    except Exception as e:
        logger.error(f"Session delete unexpected error: {e}", exc_info=True)
        log_system_error("Session Delete", f"Unexpected error: {e}")
        return jsonify({'error': 'Terjadi kesalahan tak terduga'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    # Jika GET, kembalikan ke halaman profil
    if request.method == 'GET':
        return redirect(url_for('profile'))

    # POST: proses perubahan password
    current_password = request.form.get('current_password', '').strip()
    new_password     = request.form.get('new_password',    '').strip()
    confirm_password = request.form.get('confirm_password','').strip()

    # Validasi
    if not all([current_password, new_password, confirm_password]):
        flash('Semua field harus diisi.', 'danger')
        return redirect(url_for('profile'))

    if new_password != confirm_password:
        flash('Password baru dan konfirmasinya tidak sama.', 'danger')
        return redirect(url_for('profile'))

    if not is_valid_password(new_password):
        flash('Password baru minimal 8 karakter, mengandung huruf besar, kecil, angka, dan simbol.', 'danger')
        return redirect(url_for('profile'))

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            flash('Koneksi ke database gagal.', 'danger')
            return redirect(url_for('profile'))

        cursor = conn.cursor(dictionary=True)
        # Ambil hash password lama
        cursor.execute("SELECT password FROM `user` WHERE id = %s", (current_user.id,))
        row = cursor.fetchone()
        if not row or not check_password_hash(row['password'], current_password):
            flash('Password saat ini salah.', 'danger')
            return redirect(url_for('profile'))

        # Hash dan update
        new_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
        cursor.execute(
            "UPDATE `user` SET password = %s, updated_at = %s WHERE id = %s",
            (new_hash, datetime.now(pytz.timezone('Asia/Jakarta')), current_user.id)
        )
        conn.commit()

        log_activity(
            user_id=current_user.id,
            action='password_change',
            ip_address=request.remote_addr or 'unknown',
            user_agent=request.user_agent.string or 'unknown',
            description=f"User {current_user.username} changed password"
        )

        flash('Password berhasil diubah!', 'success')
    except Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Password change MySQL error: {e}", exc_info=True)
        log_system_error("Profile", f"Password change error: {e}")
        flash('Gagal mengubah password. Silakan coba lagi.', 'danger')
    except Exception as e:
        logger.error(f"Password change unexpected error: {e}", exc_info=True)
        log_system_error("Profile", f"Unexpected password change error: {e}")
        flash('Terjadi kesalahan tak terduga.', 'danger')
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

    return redirect(url_for('profile'))



@app.template_filter('format_datetime')
def format_datetime(value, format="%d %b %Y %H:%M"):
    if isinstance(value, datetime):
        return value.strftime(format)
    return value


@app.route('/api/search')
@login_required
def api_search():
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify({'results': []})

    # Sanitasi input, misal escape karakter khusus jika perlu
    sanitized_query = sanitize_input(query)

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'results': [], 'error': 'Database connection failed'}), 500

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, title, category, created_at 
            FROM archives 
            WHERE user_id = %s AND title LIKE %s
            ORDER BY created_at DESC
            LIMIT 20
            """,
            (current_user.id, f"%{sanitized_query}%")
        )
        results = cursor.fetchall()

        # Log aktivitas pencarian user (optional tapi direkomendasikan)
        log_activity(
            current_user.id,
            'search_archives',
            request.remote_addr,
            request.user_agent.string,
            f"User {current_user.username} melakukan pencarian dengan query: {sanitized_query}"
        )

        return jsonify({'results': results})
    except Error as e:
        logger.error(f"Search error: {e}")
        log_system_error("Search", f"Search error: {e}")
        return jsonify({'results': [], 'error': 'An error occurred while searching'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


# Archive list route
@app.route('/archives', methods=['GET'])
@login_required
def archive_list():
    """
    Display a paginated list of user archives with search, filter, and sort capabilities.
    
    Args:
        page (int): Page number (default: 1)
        sort (str): Sort order (newest, oldest, title_asc, title_desc)
        query (str): Search query for title
        category_id (int): Filter by category ID
        letter_type (str): Filter by letter type (in, out)
        date_range (str): Filter by time period (today, week, month, year)
    
    Returns:
        Rendered archive_list.html template with archives and filters
    """
    page = request.args.get('page', default=1, type=int)
    sort = request.args.get('sort', default='newest', type=str).lower()
    query = request.args.get('query', default='', type=str).strip()
    category_id = request.args.get('category_id', default='', type=str).strip()
    letter_type = request.args.get('letter_type', default='', type=str).strip()
    date_range = request.args.get('date_range', default='', type=str).strip()
    per_page = 10
    offset = max(0, (page - 1) * per_page)
    error_id = str(uuid.uuid4())

    # Validate inputs
    if page < 1:
        flash('Nomor halaman tidak valid.', 'danger')
        return redirect(url_for('archive_list'))

    sort_options = {
        'newest': 'archives.created_at DESC',
        'oldest': 'archives.created_at ASC',
        'title_asc': 'archives.title ASC',
        'title_desc': 'archives.title DESC'
    }
    order_by = sort_options.get(sort, 'archives.created_at DESC')

    valid_date_ranges = ['today', 'week', 'month', 'year']
    if date_range and date_range not in valid_date_ranges:
        flash('Rentang waktu tidak valid.', 'danger')
        date_range = ''

    valid_letter_types = ['in', 'out']
    if letter_type and letter_type not in valid_letter_types:
        flash('Jenis surat tidak valid.', 'danger')
        letter_type = ''

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            flash('Gagal terhubung ke database.', 'danger')
            logger.error(f"[{error_id}] Archive list: Database connection failed")
            log_system_error(
                module="Archive",
                error_message=f"Database connection failed [{error_id}]",
                ip_address=request.remote_addr or 'unknown',
                user_id=current_user.id,
                details={'route': request.path, 'sort': sort, 'query': query, 'category_id': category_id, 'letter_type': letter_type, 'date_range': date_range}
            )
            return render_template(
                'archive_list.html',
                archives=[],
                categories=[],
                total_pages=0,
                current_page=page,
                sort=sort,
                title='Daftar Arsip',
                query=query,
                category_id=category_id,
                letter_type=letter_type,
                date_range=date_range,
                csrf_token=generate_csrf(),
                result_count=0
            )

        cursor = conn.cursor(dictionary=True)

        # Fetch categories
        cursor.execute("SELECT id, name FROM categories ORDER BY name")
        categories = cursor.fetchall()

        # Validate category_id
        valid_category_ids = [str(cat['id']) for cat in categories]
        if category_id and category_id not in valid_category_ids:
            flash('Kategori tidak valid.', 'danger')
            category_id = ''

        # Build query
        where_clause = "WHERE archives.user_id = %s"
        params = [current_user.id]
        if query:
            where_clause += " AND archives.title LIKE %s"
            params.append(f'%{query}%')
        if category_id:
            where_clause += " AND archive_category.category_id = %s"
            params.append(category_id)
        if letter_type:
            where_clause += " AND archives.letter_type = %s"
            params.append(letter_type)
        if date_range:
            if date_range == 'today':
                where_clause += " AND DATE(archives.created_at) = CURDATE()"
            elif date_range == 'week':
                where_clause += " AND archives.created_at >= CURDATE() - INTERVAL 7 DAY"
            elif date_range == 'month':
                where_clause += " AND archives.created_at >= CURDATE() - INTERVAL 1 MONTH"
            elif date_range == 'year':
                where_clause += " AND archives.created_at >= CURDATE() - INTERVAL 1 YEAR"

        # Count total archives
        count_query = f"""
            SELECT COUNT(*) AS count 
            FROM archives 
            LEFT JOIN archive_category ON archives.id = archive_category.archive_id
            {where_clause}
        """
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()['count']
        total_pages = max(1, (total_count + per_page - 1) // per_page)

        if page > total_pages:
            flash('Halaman tidak ditemukan.', 'danger')
            return redirect(url_for('archive_list', page=total_pages, sort=sort, query=query, category_id=category_id, letter_type=letter_type, date_range=date_range))

        # Fetch archives
        query = f"""
            SELECT 
                archives.id, 
                archives.title, 
                archives.description, 
                archives.file_name, 
                archives.letter_type,
                archives.created_at, 
                categories.name AS category_name
            FROM archives
            LEFT JOIN archive_category ON archives.id = archive_category.archive_id
            LEFT JOIN categories ON archive_category.category_id = categories.id
            {where_clause}
            ORDER BY {order_by}
            LIMIT %s OFFSET %s
        """
        params.extend([per_page, offset])
        cursor.execute(query, params)
        archives = cursor.fetchall()

        # Format dates
        for archive in archives:
            archive['created_at'] = archive['created_at'].strftime('%d %b %Y')

        # Log activity
        log_activity(
            user_id=current_user.id,
            action='view_archive_list',
            ip_address=request.remote_addr or 'unknown',
            user_agent=request.user_agent.string or 'unknown',
            description=f"User {current_user.username} viewed archive list page {page} with sort {sort}",
            details={
                'page': page,
                'sort': sort,
                'query': query,
                'category_id': category_id,
                'letter_type': letter_type,
                'date_range': date_range,
                'total_count': total_count
            }
        )

        return render_template(
            'archive_list.html',
            archives=archives,
            categories=categories,
            total_pages=total_pages,
            current_page=page,
            sort=sort,
            title='Daftar Arsip',
            query=query,
            category_id=category_id,
            letter_type=letter_type,
            date_range=date_range,
            csrf_token=generate_csrf(),
            result_count=total_count
        )

    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] Archive list MySQL error: {e}", exc_info=True)
        log_system_error(
            module="Archive",
            error_message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=request.remote_addr or 'unknown',
            user_id=current_user.id,
            details={
                'error_type': type(e).__name__,
                'error_code': getattr(e, 'errno', None),
                'sql_state': getattr(e, 'sqlstate', None),
                'route': request.path,
                'sort': sort,
                'query': query,
                'category_id': category_id,
                'letter_type': letter_type,
                'date_range': date_range
            }
        )
        flash(f'Terjadi kesalahan database (ID: {error_id}). Silakan coba lagi.', 'danger')
        return render_template(
            'archive_list.html',
            archives=[],
            categories=[],
            total_pages=0,
            current_page=page,
            sort=sort,
            title='Daftar Arsip',
            query=query,
            category_id=category_id,
            letter_type=letter_type,
            date_range=date_range,
            csrf_token=generate_csrf(),
            result_count=0
        )

    except Exception as e:
        logger.error(f"[{error_id}] Archive list unexpected error: {e}", exc_info=True)
        log_system_error(
            module="Archive",
            error_message=f"Unexpected error [{error_id}]: {str(e)}",
            ip_address=request.remote_addr or 'unknown',
            user_id=current_user.id,
            details={
                'error_type': type(e).__name__,
                'route': request.path,
                'sort': sort,
                'query': query,
                'category_id': category_id,
                'letter_type': letter_type,
                'date_range': date_range
            }
        )
        flash(f'Terjadi kesalahan sistem (ID: {error_id}). Silakan coba lagi.', 'danger')
        return render_template(
            'archive_list.html',
            archives=[],
            categories=[],
            total_pages=0,
            current_page=page,
            sort=sort,
            title='Daftar Arsip',
            query=query,
            category_id=category_id,
            letter_type=letter_type,
            date_range=date_range,
            csrf_token=generate_csrf(),
            result_count=0
        )

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()



@app.route('/archives/upload', methods=['GET', 'POST'])
@login_required
def archive_upload():
    error_id = str(uuid.uuid4())
    logger.debug(f"[{error_id}] Memulai proses archive_upload")

    try:
        # Pastikan direktori Uploads ada
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        logger.debug(f"Direktori {app.config['UPLOAD_FOLDER']} dipastikan ada")

        # Fetch categories from database
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error(f"[{error_id}] Koneksi database gagal saat mengambil kategori")
            flash('Koneksi database gagal.', 'danger')
            return redirect(url_for('archive_upload'))

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name FROM categories ORDER BY name")
        categories = cursor.fetchall()
        cursor.close()
        conn.close()

        if request.method == 'POST':
            logger.debug(f"[{error_id}] Menerima permintaan POST")

            # Validasi CSRF
            try:
                validate_csrf(request.form.get('csrf_token'))
                logger.debug(f"[{error_id}] CSRF token valid")
            except Exception as e:
                logger.error(f"[{error_id}] CSRF validation failed: {e}")
                flash('CSRF token tidak valid.', 'danger')
                return redirect(url_for('archive_upload'))

            # Validasi input
            title = request.form.get('title', '').strip()
            category_id = request.form.get('category_id', '').strip()
            letter_type = request.form.get('letter_type', '').strip()
            description = request.form.get('description', '').strip()
            is_public = request.form.get('is_public', 'off') == 'on'

            if not title or len(title) > 255:
                logger.debug(f"[{error_id}] Validasi gagal: Judul tidak valid")
                flash('Judul wajib diisi dan maksimal 255 karakter.', 'danger')
                return redirect(url_for('archive_upload'))

            if not category_id or not any(cat['id'] == int(category_id) for cat in categories):
                logger.debug(f"[{error_id}] Validasi gagal: Kategori tidak valid")
                flash('Kategori surat wajib dipilih.', 'danger')
                return redirect(url_for('archive_upload'))

            if letter_type not in ['in', 'out']:
                logger.debug(f"[{error_id}] Validasi gagal: Jenis surat tidak valid")
                flash('Jenis surat wajib dipilih (Surat Masuk atau Surat Keluar).', 'danger')
                return redirect(url_for('archive_upload'))

            if description and len(description) > 500:
                logger.debug(f"[{error_id}] Validasi gagal: Deskripsi terlalu panjang")
                flash('Nomor surat maksimal 500 karakter.', 'danger')
                return redirect(url_for('archive_upload'))

            # Validasi file
            if 'file' not in request.files:
                logger.debug(f"[{error_id}] Validasi gagal: Tidak ada file")
                flash('Silakan pilih file terlebih dahulu.', 'danger')
                return redirect(url_for('archive_upload'))

            file = request.files['file']
            if file.filename == '':
                logger.debug(f"[{error_id}] Validasi gagal: Nama file kosong")
                flash('Tidak ada file yang dipilih.', 'danger')
                return redirect(url_for('archive_upload'))

            filename = secure_filename(file.filename)
            if not allowed_file(filename):
                logger.debug(f"[{error_id}] Validasi gagal: Jenis file tidak diizinkan")
                flash(f'Jenis file tidak didukung. Hanya {", ".join(app.config["ALLOWED_EXTENSIONS"])} yang diperbolehkan.', 'danger')
                return redirect(url_for('archive_upload'))

            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            if file_size > app.config['MAX_FILE_SIZE']:
                logger.debug(f"[{error_id}] Validasi gagal: Ukuran file terlalu besar")
                flash(f'Ukuran file terlalu besar (maksimal {app.config["MAX_FILE_SIZE"] // (1024 * 1024)}MB).', 'danger')
                return redirect(url_for('archive_upload'))

            # Simpan file
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            logger.debug(f"[{error_id}] Mencoba menyimpan file ke {file_path}")
            file.save(file_path)

            if not os.path.exists(file_path):
                logger.error(f"[{error_id}] Gagal menyimpan file: File tidak ditemukan di {file_path}")
                flash('Gagal menyimpan file.', 'danger')
                return redirect(url_for('archive_upload'))
            logger.debug(f"[{error_id}] File berhasil disimpan ke {file_path}")

            # Simpan ke database
            conn = get_db_connection()
            if not conn or not conn.is_connected():
                logger.error(f"[{error_id}] Koneksi database gagal")
                cleanup_uploaded_file(file_path)
                flash('Koneksi database gagal.', 'danger')
                return redirect(url_for('archive_upload'))

            cursor = conn.cursor()
            try:
                # Insert into archives table
                query = """
                    INSERT INTO archives (
                        user_id, title, description, file_name, file_path,
                        file_type, file_size, is_public, letter_type, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                params = (
                    current_user.id,
                    title,
                    description or None,
                    filename,
                    file_path,
                    mimetypes.guess_type(filename)[0] or 'application/octet-stream',
                    file_size,
                    is_public,
                    letter_type,
                    datetime.now(pytz.timezone('Asia/Jakarta')),
                    datetime.now(pytz.timezone('Asia/Jakarta'))
                )
                cursor.execute(query, params)
                archive_id = cursor.lastrowid
                logger.debug(f"[{error_id}] Metadata arsip disimpan dengan archive_id: {archive_id}")

                # Insert into archive_category table
                category_query = """
                    INSERT INTO archive_category (archive_id, category_id, assigned_by)
                    VALUES (%s, %s, %s)
                """
                cursor.execute(category_query, (archive_id, category_id, current_user.id))
                logger.debug(f"[{error_id}] Relasi kategori disimpan untuk category_id: {category_id}")

                # Log aktivitas
                log_activity(
                    user_id=current_user.id,
                    action='upload_archive',
                    ip_address=request.remote_addr or 'unknown',
                    user_agent=request.user_agent.string or 'unknown',
                    description=f"Pengguna {current_user.username} mengunggah arsip '{title}' ({'Surat Masuk' if letter_type == 'in' else 'Surat Keluar'}) dengan kategori ID {category_id}",
                    details={'archive_id': archive_id, 'filename': filename, 'category_id': category_id, 'letter_type': letter_type}
                )

                # Simpan log akses
                access_query = """
                    INSERT INTO archive_access_log (
                        archive_id, user_id, access_type, ip_address, access_time
                    ) VALUES (%s, %s, %s, %s, %s)
                """
                access_params = (
                    archive_id, current_user.id, 'edit',
                    request.remote_addr or 'unknown',
                    datetime.now(pytz.timezone('Asia/Jakarta'))
                )
                cursor.execute(access_query, access_params)

                conn.commit()
                logger.debug(f"[{error_id}] Transaksi database berhasil")
                flash('Arsip berhasil diunggah.', 'success')
                return redirect(url_for('archive_list'))

            except mysql.connector.Error as e:
                conn.rollback()
                cleanup_uploaded_file(file_path)
                logger.error(f"[{error_id}] MySQL error: {e}")
                log_system_error(
                    module="Archive",
                    message=f"MySQL error [{error_id}]: {str(e)}",
                    ip_address=request.remote_addr or 'unknown',
                    user_id=current_user.id
                )
                flash(f'Gagal menyimpan arsip (ID: {error_id}).', 'danger')
                return redirect(url_for('archive_upload'))

            finally:
                cursor.close()
                conn.close()
                logger.debug(f"[{error_id}] Koneksi database ditutup")

        # GET request - tampilkan halaman upload
        logger.debug(f"[{error_id}] Merender halaman archive_upload.html")
        return render_template(
            'archive_upload.html',
            title='Unggah Arsip',
            categories=categories,
            csrf_token=generate_csrf()
        )

    except Exception as e:
        logger.error(f"[{error_id}] Unexpected error in archive_upload: {e}", exc_info=True)
        log_system_error(
            module="Archive",
            message=f"Unexpected error [{error_id}]: {str(e)}",
            ip_address=request.remote_addr or 'unknown',
            user_id=current_user.id
        )
        flash(f'Terjadi kesalahan sistem (ID: {error_id}). Silakan coba lagi.', 'danger')
        return redirect(url_for('archive_upload'))



@app.route('/archives/<int:archive_id>', methods=['GET'])
@login_required
def archive_detail(archive_id):
    """
    Display details of a specific archive.
    
    Args:
        archive_id (int): ID of the archive to display
    
    Returns:
        Rendered archive_detail.html template or redirect on error
    """
    conn = None
    cursor = None
    error_id = str(uuid.uuid4())

    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            flash('Gagal terhubung ke database.', 'danger')
            logger.error(f"[{error_id}] Archive detail: Database connection failed")
            return redirect(url_for('archive_list'))

        cursor = conn.cursor(dictionary=True)

        # Fetch archive details
        cursor.execute(
            """
            SELECT archives.id, archives.title, archives.description, archives.file_name, 
                   archives.file_path, archives.file_type, archives.file_size, 
                   archives.is_public, archives.letter_type, 
                   archives.category AS archive_category, archives.created_at, 
                   archives.updated_at, categories.name AS category_name
            FROM archives
            LEFT JOIN archive_category ON archives.id = archive_category.archive_id
            LEFT JOIN categories ON archive_category.category_id = categories.id
            WHERE archives.id = %s AND archives.user_id = %s
            """,
            (archive_id, current_user.id)
        )
        archive = cursor.fetchone()

        if not archive:
            flash('Arsip tidak ditemukan atau Anda tidak memiliki akses.', 'danger')
            return redirect(url_for('archive_list'))

        # Fetch tags
        cursor.execute(
            "SELECT tag_name FROM archive_tags WHERE archive_id = %s",
            (archive_id,)
        )
        tags = [row['tag_name'] for row in cursor.fetchall()]

        # Format data
        archive['file_size'] = format_file_size(archive['file_size'])
        tz = pytz.timezone('Asia/Jakarta')
        archive['created_at'] = archive['created_at'].astimezone(tz).strftime('%d %B %Y, %H:%M')
        archive['updated_at'] = archive['updated_at'].astimezone(tz).strftime('%d %B %Y, %H:%M') if archive['updated_at'] else '-'

        # Log activity
        log_activity(
            user_id=current_user.id,
            action='view_archive',
            ip_address=request.remote_addr or 'unknown',
            user_agent=request.user_agent.string or 'unknown',
            description=f"User {current_user.username} viewed archive: {archive['title']}",
            details={'archive_id': archive_id}
        )

        return render_template(
            'archive_detail.html',
            archive=archive,
            tags=tags,
            title='Detail Arsip',
            archive_id=archive_id,
            csrf_token=generate_csrf()
        )

    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] Archive detail MySQL error: {e}", exc_info=True)
        log_system_error(
            module="Archive",
            message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=request.remote_addr or 'unknown',
            user_id=current_user.id,
            details={'route': request.path, 'archive_id': archive_id}
        )
        flash(f'Terjadi kesalahan database (ID: {error_id}).', 'danger')
        return redirect(url_for('archive_list'))

    except Exception as e:
        logger.error(f"[{error_id}] Archive detail unexpected error: {e}", exc_info=True)
        log_system_error(
            module="Archive",
            message=f"Unexpected error [{error_id}]: {str(e)}",
            ip_address=request.remote_addr or 'unknown',
            user_id=current_user.id,
            details={'route': request.path, 'archive_id': archive_id}
        )
        flash(f'Terjadi kesalahan sistem (ID: {error_id}).', 'danger')
        return redirect(url_for('archive_list'))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route('/archives/delete/<int:id>', methods=['DELETE'])
@login_required
def archive_delete(id):
    error_id = str(uuid.uuid4())
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error(f"[{error_id}] Archive delete: Database connection failed")
            return jsonify({'success': False, 'error': 'Koneksi database gagal'}), 500

        cursor = conn.cursor()
        cursor.execute("SELECT user_id, file_path FROM archives WHERE id = %s", (id,))
        archive = cursor.fetchone()
        if not archive:
            logger.error(f"[{error_id}] Archive not found: ID {id}")
            return jsonify({'success': False, 'error': 'Arsip tidak ditemukan'}), 404
        if archive[0] != current_user.id and not has_permission(current_user.id, 'delete_any_archive'):
            logger.error(f"[{error_id}] User {current_user.id} not authorized to delete archive {id}")
            return jsonify({'success': False, 'error': 'Tidak diizinkan'}), 403

        file_path = archive[1]
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.debug(f"[{error_id}] Deleted file: {file_path}")

        cursor.execute("DELETE FROM archives WHERE id = %s", (id,))
        cursor.execute("DELETE FROM archive_access_log WHERE archive_id = %s", (id,))
        cursor.execute("DELETE FROM archive_category WHERE archive_id = %s", (id,))
        cursor.execute("DELETE FROM archive_tag WHERE archive_id = %s", (id,))
        conn.commit()

        log_activity(
            user_id=current_user.id,
            action='delete_archive',
            ip_address=request.remote_addr or 'unknown',
            user_agent=request.user_agent.string or 'unknown',
            description=f"Pengguna {current_user.username} menghapus arsip ID {id}",
            details={'archive_id': id}
        )
        logger.info(f"[{error_id}] Archive deleted successfully: ID {id}")
        return jsonify({'success': True, 'message': 'Arsip berhasil dihapus'})

    except Error as e:
        logger.error(f"[{error_id}] Archive delete MySQL error: {e}")
        if conn:
            conn.rollback()
        return jsonify({'success': False, 'error': f'Gagal menghapus arsip (ID: {error_id})'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/archives/download/<int:archive_id>', methods=['GET'])
@login_required
def download_archive(archive_id):
    """
    Download an archive file.
    
    Args:
        archive_id (int): ID of the archive to download
    
    Returns:
        File download response or redirect on error
    """
    conn = None
    cursor = None
    error_id = str(uuid.uuid4())

    try:
        # Validate upload folder configuration
        upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
        if not os.path.isdir(upload_folder):
            flash('Folder penyimpanan file tidak ditemukan.', 'danger')
            logger.error(f"[{error_id}] Archive download: Upload folder {upload_folder} does not exist")
            return redirect(url_for('archive_list'))

        conn = get_db_connection()
        if not conn or not conn.is_connected():
            flash('Gagal terhubung ke database.', 'danger')
            logger.error(f"[{error_id}] Archive download: Database connection failed")
            return redirect(url_for('archive_list'))

        cursor = conn.cursor(dictionary=True)

        # Fetch archive
        cursor.execute(
            """
            SELECT file_name, file_path, title
            FROM archives
            WHERE id = %s AND user_id = %s
            """,
            (archive_id, current_user.id)
        )
        archive = cursor.fetchone()

        if not archive:
            flash('Arsip tidak ditemukan atau Anda tidak memiliki akses.', 'danger')
            logger.warning(f"[{error_id}] Archive ID {archive_id} not found or access denied for user {current_user.id}")
            return redirect(url_for('archive_list'))

        # Sanitize file path
        file_name = os.path.basename(archive['file_path'])
        file_path = os.path.join(upload_folder, file_name)
        # Normalize to prevent directory traversal
        file_path = os.path.normpath(file_path)
        if not file_path.startswith(os.path.abspath(upload_folder)):
            flash('Akses ke file tidak valid.', 'danger')
            logger.error(f"[{error_id}] Invalid file path access attempt: {file_path}")
            return redirect(url_for('archive_list'))

        if not os.path.isfile(file_path):
            flash('File arsip tidak ada di server.', 'danger')
            logger.error(f"[{error_id}] File not found: {file_path}")
            return redirect(url_for('archive_list'))

        # Log download to archive_access_log
        tz = pytz.timezone('Asia/Jakarta')
        access_time = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            """
            INSERT INTO archive_access_log (archive_id, user_id, access_type, ip_address, created_at_time)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (archive_id, current_user.id, 'download', request.remote_addr or 'unknown', access_time)
        )
        conn.commit()

        # Log activity
        log_activity(
            user_id=current_user.id,
            action='download_archive',
            ip_address=request.remote_addr or 'unknown',
            user_agent=request.user_agent.string or 'anonymous',
            description=f"User {current_user.id} downloaded archive: {archive['title']}",
            details={
                'archive_id': archive_id,
                'filename': archive['file_name'],
                'ip_address': request.remote_addr
            }
        )

        return send_file(
            file_path,
            as_attachment=True,
            download_name=archive['file_name'],
            mimetype='application/octet-stream'
        )

    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] error: {e}", exc_info=True)
        log_system_error(
            module="Archive",
            message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address='unknown',
            details={'route': request.path, 'archive_id': str(archive_id)}
        )
        flash(f'Terjadi kesalahan database (ID: {error_id}).', 'warning')
        return redirect(url_for('archive_list'))

    except Exception as e:
        logger.error(f"[{error_id}] error: {e}", exc_info=True)
        log_system_error(
            module="Archive",
            message=f"Unexpected error [{error_id}]: {str(e)}",
            ip_address='unknown',
            details={'route': str(request.path), 'archive_id': str(archive_id)}
        )
        flash(f'Terjadi kesalahan sistem (ID: {error_id}).', 'warning')
        return redirect(url_for('archive_list'))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


# Rute dashboard
@app.route('/admin')
@app.route('/admin/')
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    """Admin Dashboard Route"""
    error_id = str(uuid.uuid4())
    ip_address = request.remote_addr or 'unknown'
    user_agent = request.user_agent.string or 'unknown'
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error(f"[{error_id}] Admin dashboard: Database connection failed")
            flash('Gagal terhubung ke database.', 'danger')
            return render_template('admin_dashboard.html', 
                                 dashboard_data={}, 
                                 title='Admin Dashboard')
        
        cursor = conn.cursor(dictionary=True)
        
        # Get dashboard statistics
        dashboard_data = {}
        
        # Total Users
        cursor.execute("SELECT COUNT(*) as count FROM user WHERE is_active = 1")
        dashboard_data['totalUsers'] = cursor.fetchone()['count']
        
        # Total Archives
        cursor.execute("SELECT COUNT(*) as count FROM archives")
        dashboard_data['totalArchives'] = cursor.fetchone()['count']
        
        # Total System Logs
        cursor.execute("SELECT COUNT(*) as count FROM system_logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)")
        dashboard_data['totalLogs'] = cursor.fetchone()['count']
        
        # Unread Notifications
        cursor.execute("SELECT COUNT(*) as count FROM notifications WHERE is_read = 0")
        dashboard_data['totalNotifications'] = cursor.fetchone()['count']
        
        # Recent System Logs (last 10)
        cursor.execute("""
            SELECT id, level, module, message, user_id, ip_address, created_at
            FROM system_logs 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        dashboard_data['recentLogs'] = cursor.fetchall()
        
        # Recent Notifications (last 10)
        cursor.execute("""
            SELECT id, user_id, message, is_read, created_at
            FROM notifications 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        dashboard_data['recentNotifications'] = cursor.fetchall()
        
        # Log activity
        log_activity(
            user_id=current_user.id,
            action='view_admin_dashboard',
            ip_address=ip_address,
            user_agent=user_agent,
            description=f"Admin {current_user.username} viewed dashboard",
            details=json.dumps({'user_count': dashboard_data['totalUsers']})
        )
        
        return render_template(
            'admin_dashboard.html',
            dashboard_data=dashboard_data,
            title='Admin Dashboard',
            csrf_token=generate_csrf(),
            current_year=datetime.now(pytz.timezone('Asia/Jakarta')).year
        )
        
    except Exception as e:
        logger.error(f"[{error_id}] Admin dashboard error: {e}", exc_info=True)
        log_system_error(
            module="Admin Dashboard",
            message=f"Dashboard error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id
        )
        flash(f'Terjadi kesalahan sistem (ID: {error_id}).', 'danger')
        return render_template('admin_dashboard.html', 
                             dashboard_data={}, 
                             title='Admin Dashboard')
        
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# ==================== USER MANAGEMENT ====================
@app.route('/admin/users', methods=['GET', 'POST'])
@app.route('/admin/user-management', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_management():
    error_id = str(uuid.uuid4())
    ip_address = request.remote_addr or 'unknown'
    user_agent = request.user_agent.string or 'unknown'
    current_time = datetime.now(pytz.timezone('Asia/Jakarta'))
    search_query = request.args.get('q', '').strip().lower()
    form_data = {}
    user_id = None
    roles = []

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error(f"[{error_id}] Admin user management: Database connection failed")
            flash('Gagal terhubung ke database.', 'danger')
            return render_template(
                'admin_user_management.html',
                users=[],
                roles=roles,
                search_query=search_query,
                form_data=form_data,
                user_id=user_id,
                title='Manajemen Pengguna',
                csrf_token=generate_csrf(),
                current_year=current_time.year
            )

        cursor = conn.cursor(dictionary=True)

        # Fetch roles for dropdown
        cursor.execute("SELECT id, name FROM roles ORDER BY name")
        roles = cursor.fetchall()

        # Handle POST requests
        if request.method == 'POST':
            csrf_token = request.form.get('csrf_token')
            if not csrf_token:
                flash('CSRF token tidak ditemukan. Silakan coba lagi.', 'danger')
                return redirect(url_for('admin_user_management'))

            action = request.form.get('action')
            if action == 'delete':
                user_id_delete = request.form.get('user_id')
                if not user_id_delete or not user_id_delete.isdigit():
                    flash('ID pengguna tidak valid.', 'danger')
                    return redirect(url_for('admin_user_management'))

                if int(user_id_delete) == current_user.id:
                    flash('Anda tidak dapat menghapus akun sendiri.', 'danger')
                    return redirect(url_for('admin_user_management'))

                cursor.execute("SELECT id, username, is_superadmin FROM user WHERE id = %s", (user_id_delete,))
                user_to_delete = cursor.fetchone()
                if not user_to_delete:
                    flash('Pengguna tidak ditemukan.', 'danger')
                    return redirect(url_for('admin_user_management'))

                if user_to_delete['is_superadmin'] and not current_user.is_superadmin:
                    flash('Hanya Superadmin yang dapat menghapus pengguna Superadmin.', 'danger')
                    return redirect(url_for('admin_user_management'))

                try:
                    cursor.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id_delete,))
                    cursor.execute("DELETE FROM user_permissions WHERE user_id = %s", (user_id_delete,))
                    cursor.execute("DELETE FROM user_logs WHERE user_id = %s", (user_id_delete,))
                    cursor.execute("DELETE FROM user WHERE id = %s", (user_id_delete,))
                    conn.commit()

                    log_activity(
                        user_id=current_user.id,
                        action='delete_user',
                        ip_address=ip_address,
                        user_agent=user_agent,
                        description=f"Admin {current_user.username} menghapus pengguna: {user_to_delete['username']}",
                        details={'deleted_user_id': user_id_delete, 'deleted_username': user_to_delete['username']}
                    )
                    flash('Pengguna berhasil dihapus!', 'success')
                    return redirect(url_for('admin_user_management'))
                except Exception as e:
                    conn.rollback()
                    logger.error(f"[{error_id}] Gagal menghapus pengguna: {e}")
                    flash(f'Gagal menghapus pengguna (ID: {error_id}).', 'danger')
                    return redirect(url_for('admin_user_management'))
                finally:
                    if cursor:
                        cursor.close()
                    if conn and conn.is_connected():
                        conn.close()
                    conn = get_db_connection()
                    cursor = conn.cursor(dictionary=True)

            # Handle user creation/update
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '').strip()
            full_name = request.form.get('full_name', '').strip()
            phone = request.form.get('phone', '').strip() or None
            role_id = request.form.get('role_id', '').strip()
            email_verified = request.form.get('email_verified') == 'on'
            is_admin = request.form.get('is_admin') == 'on'
            is_superadmin = request.form.get('is_superadmin') == 'on'
            is_active = request.form.get('is_active') == 'on'
            user_id = request.form.get('user_id')

            # Validate input
            if not username or len(username) < 4 or len(username) > 80 or not re.match(r'^[a-zA-Z0-9_]+$', username):
                flash('Username harus 4-80 karakter, hanya huruf, angka, atau underscore.', 'danger')
                form_data = {
                    'username': username, 'email': email, 'full_name': full_name, 'phone': phone,
                    'role_id': role_id, 'email_verified': email_verified, 'is_admin': is_admin,
                    'is_superadmin': is_superadmin, 'is_active': is_active
                }
                return render_template(
                    'admin_user_management.html',
                    users=[],
                    roles=roles,
                    search_query=search_query,
                    form_data=form_data,
                    user_id=user_id,
                    title='Manajemen Pengguna',
                    csrf_token=generate_csrf(),
                    current_year=current_time.year
                )

            if not email or len(email) > 120 or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                flash('Masukkan alamat email yang valid (maks 120 karakter).', 'danger')
                form_data = {
                    'username': username, 'email': email, 'full_name': full_name, 'phone': phone,
                    'role_id': role_id, 'email_verified': email_verified, 'is_admin': is_admin,
                    'is_superadmin': is_superadmin, 'is_active': is_active
                }
                return render_template(
                    'admin_user_management.html',
                    users=[],
                    roles=roles,
                    search_query=search_query,
                    form_data=form_data,
                    user_id=user_id,
                    title='Manajemen Pengguna',
                    csrf_token=generate_csrf(),
                    current_year=current_time.year
                )

            if not full_name or len(full_name) > 255:
                flash('Nama lengkap diperlukan (maks 255 karakter).', 'danger')
                form_data = {
                    'username': username, 'email': email, 'full_name': full_name, 'phone': phone,
                    'role_id': role_id, 'email_verified': email_verified, 'is_admin': is_admin,
                    'is_superadmin': is_superadmin, 'is_active': is_active
                }
                return render_template(
                    'admin_user_management.html',
                    users=[],
                    roles=roles,
                    search_query=search_query,
                    form_data=form_data,
                    user_id=user_id,
                    title='Manajemen Pengguna',
                    csrf_token=generate_csrf(),
                    current_year=current_time.year
                )

            if phone and (len(phone) > 15 or not re.match(r'^[0-9+()-]{0,15}$', phone)):
                flash('Nomor telepon tidak valid (maks 15 karakter).', 'danger')
                form_data = {
                    'username': username, 'email': email, 'full_name': full_name, 'phone': phone,
                    'role_id': role_id, 'email_verified': email_verified, 'is_admin': is_admin,
                    'is_superadmin': is_superadmin, 'is_active': is_active
                }
                return render_template(
                    'admin_user_management.html',
                    users=[],
                    roles=roles,
                    search_query=search_query,
                    form_data=form_data,
                    user_id=user_id,
                    title='Manajemen Pengguna',
                    csrf_token=generate_csrf(),
                    current_year=current_time.year
                )

            if not role_id or not role_id.isdigit() or int(role_id) not in [r['id'] for r in roles]:
                flash('Peran tidak valid.', 'danger')
                form_data = {
                    'username': username, 'email': email, 'full_name': full_name, 'phone': phone,
                    'role_id': role_id, 'email_verified': email_verified, 'is_admin': is_admin,
                    'is_superadmin': is_superadmin, 'is_active': is_active
                }
                return render_template(
                    'admin_user_management.html',
                    users=[],
                    roles=roles,
                    search_query=search_query,
                    form_data=form_data,
                    user_id=user_id,
                    title='Manajemen Pengguna',
                    csrf_token=generate_csrf(),
                    current_year=current_time.year
                )

            # Validate password
            if not user_id and not password:
                flash('Kata sandi diperlukan untuk pengguna baru.', 'danger')
                form_data = {
                    'username': username, 'email': email, 'full_name': full_name, 'phone': phone,
                    'role_id': role_id, 'email_verified': email_verified, 'is_admin': is_admin,
                    'is_superadmin': is_superadmin, 'is_active': is_active
                }
                return render_template(
                    'admin_user_management.html',
                    users=[],
                    roles=roles,
                    search_query=search_query,
                    form_data=form_data,
                    user_id=user_id,
                    title='Manajemen Pengguna',
                    csrf_token=generate_csrf(),
                    current_year=current_time.year
                )

            if password and (len(password) < 8 or len(password) > 128 or
                            not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,128}$', password)):
                flash('Kata sandi harus 8-128 karakter, mengandung huruf besar, kecil, dan angka.', 'danger')
                form_data = {
                    'username': username, 'email': email, 'full_name': full_name, 'phone': phone,
                    'role_id': role_id, 'email_verified': email_verified, 'is_admin': is_admin,
                    'is_superadmin': is_superadmin, 'is_active': is_active
                }
                return render_template(
                    'admin_user_management.html',
                    users=[],
                    roles=roles,
                    search_query=search_query,
                    form_data=form_data,
                    user_id=user_id,
                    title='Manajemen Pengguna',
                    csrf_token=generate_csrf(),
                    current_year=current_time.year
                )

            if is_superadmin and not current_user.is_superadmin:
                flash('Hanya Superadmin yang dapat membuat pengguna Superadmin.', 'danger')
                return redirect(url_for('admin_user_management'))

            try:
                if user_id:
                    cursor.execute("SELECT id, username, email FROM user WHERE id = %s", (user_id,))
                    existing_user = cursor.fetchone()
                    if not existing_user:
                        flash('Pengguna tidak ditemukan.', 'danger')
                        return redirect(url_for('admin_user_management'))

                    cursor.execute("""
                        SELECT id FROM user 
                        WHERE (username = %s OR email = %s) AND id != %s
                    """, (username, email, user_id))
                    if cursor.fetchone():
                        flash('Username atau email sudah digunakan.', 'danger')
                        return redirect(url_for('admin_user_management'))

                    update_query = """
                        UPDATE user 
                        SET username = %s, email = %s, full_name = %s, phone = %s, 
                            is_admin = %s, is_superadmin = %s, is_active = %s, 
                            email_verified = %s, updated_at = %s
                    """
                    update_params = [username, email, full_name, phone, is_admin, is_superadmin, is_active, 
                                     email_verified, current_time]

                    if password:
                        update_query += ", password = %s"
                        update_params.append(generate_password_hash(password))

                    update_query += " WHERE id = %s"
                    update_params.append(user_id)

                    cursor.execute(update_query, update_params)

                    # Update role
                    cursor.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id,))
                    cursor.execute("""
                        INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)
                        VALUES (%s, %s, %s, %s)
                    """, (user_id, role_id, current_time, current_user.id))
                    
                    log_activity(
                        user_id=current_user.id,
                        action='update_user',
                        ip_address=ip_address,
                        user_agent=user_agent,
                        description=f"Admin {current_user.username} memperbarui pengguna: {username}",
                        details={
                            'username': username, 'user_id': int(user_id), 'role_id': int(role_id),
                            'changes': {
                                'is_admin': is_admin, 'is_superadmin': is_superadmin, 
                                'is_active': is_active, 'email_verified': email_verified,
                                'password_updated': bool(password)
                            }
                        }
                    )
                    flash('Pengguna berhasil diperbarui!', 'success')
                else:
                    cursor.execute("SELECT id FROM user WHERE username = %s OR email = %s", (username, email))
                    if cursor.fetchone():
                        flash('Username atau email sudah digunakan.', 'danger')
                        return redirect(url_for('admin_user_management'))

                    password_hash = generate_password_hash(password)
                    cursor.execute("""
                        INSERT INTO user 
                        (username, email, password, full_name, phone, 
                         is_admin, is_superadmin, is_active, email_verified, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (username, email, password_hash, full_name, phone, 
                          is_admin, is_superadmin, is_active, email_verified, current_time))
                    new_user_id = cursor.lastrowid

                    # Assign role
                    cursor.execute("""
                        INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)
                        VALUES (%s, %s, %s, %s)
                    """, (new_user_id, role_id, current_time, current_user.id))

                    log_activity(
                        user_id=current_user.id,
                        action='create_user',
                        ip_address=ip_address,
                        user_agent=user_agent,
                        description=f"Admin {current_user.username} membuat pengguna: {username}",
                        details={'username': username, 'user_id': new_user_id, 'role_id': int(role_id)}
                    )
                    flash('Pengguna berhasil dibuat!', 'success')

                conn.commit()
                return redirect(url_for('admin_user_management'))

            except Exception as e:
                conn.rollback()
                logger.error(f"[{error_id}] Gagal membuat/memperbarui pengguna: {e}")
                flash(f'Gagal membuat/memperbarui pengguna (ID: {error_id}).', 'danger')
                return redirect(url_for('admin_user_management'))
            finally:
                if cursor:
                    cursor.close()
                if conn and conn.is_connected():
                    conn.close()
                conn = get_db_connection()
                cursor = conn.cursor(dictionary=True)

        # GET REQUEST: Display all users and form
        user_id = request.args.get('user_id')
        if user_id and user_id.isdigit():
            cursor.execute("""
                SELECT u.id, u.username, u.email, u.full_name, u.phone, 
                       u.is_admin, u.is_superadmin, u.is_active, u.email_verified,
                       ur.role_id
                FROM user u
                LEFT JOIN user_roles ur ON u.id = ur.user_id
                WHERE u.id = %s
            """, (user_id,))
            user_to_edit = cursor.fetchone()
            if user_to_edit:
                form_data = {
                    'username': user_to_edit['username'],
                    'email': user_to_edit['email'],
                    'full_name': user_to_edit['full_name'],
                    'phone': user_to_edit['phone'],
                    'role_id': user_to_edit['role_id'],
                    'is_admin': bool(user_to_edit['is_admin']),
                    'is_superadmin': bool(user_to_edit['is_superadmin']),
                    'is_active': bool(user_to_edit['is_active']),
                    'email_verified': bool(user_to_edit['email_verified'])
                }

        # Fetch all users
        query = """
            SELECT u.id, u.username, u.email, u.full_name, u.phone, 
                   u.is_admin, u.is_superadmin, u.is_active, u.email_verified, 
                   u.created_at, r.name AS role_name
            FROM user u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE %s = '' OR 
                  LOWER(u.username) LIKE %s OR 
                  LOWER(u.email) LIKE %s OR 
                  LOWER(u.full_name) LIKE %s
            ORDER BY u.created_at DESC
        """
        cursor.execute(query, (
            search_query,
            f'%{search_query}%',
            f'%{search_query}%',
            f'%{search_query}%'
        ))
        users = cursor.fetchall()

        log_activity(
            user_id=current_user.id,
            action='view_admin_user_management',
            ip_address=ip_address,
            user_agent=user_agent,
            description=f"Admin {current_user.username} melihat halaman manajemen pengguna",
            details={'user_count': len(users), 'search_query': search_query}
        )

        return render_template(
            'admin_user_management.html',
            users=users,
            roles=roles,
            search_query=search_query,
            form_data=form_data,
            user_id=user_id,
            title='Manajemen Pengguna',
            csrf_token=generate_csrf(),
            current_year=current_time.year
        )

    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] MySQL error: {e}")
        log_system_error(
            module="Admin User Management",
            message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'search_query': search_query}
        )
        flash(f'Terjadi kesalahan database (ID: {error_id}).', 'danger')
        return render_template(
            'admin_user_management.html',
            users=[],
            roles=roles,
            search_query=search_query,
            form_data=form_data,
            user_id=user_id,
            title='Manajemen Pengguna',
            csrf_token=generate_csrf(),
            current_year=current_time.year
        )

    except Exception as e:
        logger.error(f"[{error_id}] Kesalahan tak terduga: {e}")
        log_system_error(
            module="Admin User Management",
            message=f"Kesalahan tak terduga [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'search_query': search_query}
        )
        flash(f'Terjadi kesalahan sistem (ID: {error_id}).', 'danger')
        return render_template(
            'admin_user_management.html',
            users=[],
            roles=roles,
            search_query=search_query,
            form_data=form_data,
            user_id=user_id,
            title='Manajemen Pengguna',
            csrf_token=generate_csrf(),
            current_year=current_time.year
        )

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()
# ==================== ARCHIVE MANAGEMENT ====================
@app.route('/admin/archives', methods=['GET', 'POST'])
@app.route('/admin/archive-management', methods=['GET', 'POST'])
@app.route('/admin/archives/download/<int:archive_id>', methods=['GET'])
@login_required
@admin_required
def admin_archive_management(archive_id=None):
    """Admin Archive Management Route with Download and Delete Functionality"""
    error_id = str(uuid.uuid4())
    ip_address = request.remote_addr or 'unknown'
    user_agent = request.user_agent.string or 'unknown'
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error(f"[{error_id}] Admin archive management: Database connection failed")
            flash('Gagal terhubung ke database.', 'danger')
            return render_template('admin_archive_management.html', archives=[], categories=[], title='Archive Management', current_year=datetime.now(pytz.timezone('Asia/Jakarta')).year)
        
        cursor = conn.cursor(dictionary=True)
        
        # Fetch categories for filter dropdown
        cursor.execute("SELECT id, name FROM categories ORDER BY name")
        categories = cursor.fetchall()
        
        # Get query parameters
        query = request.args.get('query', default='', type=str).strip()
        category_id = request.args.get('category_id', default='', type=str).strip()
        
        # Validate category_id
        valid_category_ids = [str(cat['id']) for cat in categories]
        if category_id and category_id not in valid_category_ids:
            flash('Kategori tidak valid.', 'danger')
            category_id = ''
        
        # Handle POST requests (delete archive)
        if request.method == 'POST':
            try:
                validate_csrf(request.form.get('csrf_token'))
            except CSRFError:
                flash('CSRF token tidak valid.', 'danger')
                return redirect(url_for('admin_archive_management', query=query, category_id=category_id))
            
            action = request.form.get('action')
            archive_id_form = request.form.get('archive_id')
            
            if action == 'delete' and archive_id_form:
                cursor.execute("SELECT title, user_id FROM archives WHERE id = %s", (archive_id_form,))
                archive_info = cursor.fetchone()
                
                if archive_info:
                    # Delete related archive_category entries
                    cursor.execute("DELETE FROM archive_category WHERE archive_id = %s", (archive_id_form,))
                    # Delete archive
                    cursor.execute("DELETE FROM archives WHERE id = %s", (archive_id_form,))
                    conn.commit()
                    
                    log_activity(
                        user_id=current_user.id,
                        action='delete_archive',
                        ip_address=ip_address,
                        user_agent=user_agent,
                        description=f"Admin {current_user.username} menghapus arsip: {archive_info['title']}",
                        details={'archive_id': int(archive_id_form), 'archive_title': archive_info['title']}
                    )
                    flash('Arsip berhasil dihapus!', 'success')
                else:
                    flash('Arsip tidak ditemukan.', 'danger')
            
            return redirect(url_for('admin_archive_management', query=query, category_id=category_id))
        
        # Handle download request
        if archive_id is not None:
            cursor.execute("""
                SELECT id, title, file_name, file_path, file_type, file_size, user_id
                FROM archives 
                WHERE id = %s
            """, (archive_id,))
            archive = cursor.fetchone()
            
            if not archive:
                flash('Arsip tidak ditemukan.', 'danger')
                return redirect(url_for('admin_archive_management', query=query, category_id=category_id))
            
            file_path = archive['file_path']
            if not os.path.exists(file_path):
                logger.error(f"[{error_id}] File tidak ditemukan: {file_path}")
                flash('File tidak ditemukan di server.', 'danger')
                return redirect(url_for('admin_archive_management', query=query, category_id=category_id))
            
            log_activity(
                user_id=current_user.id,
                action='download_archive',
                ip_address=ip_address,
                user_agent=user_agent,
                description=f"Admin {current_user.username} mengunduh arsip: {archive['title']}",
                details={
                    'archive_id': archive['id'],
                    'archive_title': archive['title'],
                    'file_name': archive['file_name'],
                    'file_type': archive['file_type'],
                    'file_size': archive['file_size']
                }
            )
            
            try:
                return send_file(
                    file_path,
                    as_attachment=True,
                    download_name=archive['file_name'],
                    mimetype=f'application/{archive["file_type"]}'
                )
            except Exception as e:
                logger.error(f"[{error_id}] Gagal mengirim file: {e}", exc_info=True)
                flash(f'Gagal mengunduh file (ID: {error_id}).', 'danger')
                return redirect(url_for('admin_archive_management', query=query, category_id=category_id))
        
        # GET request: Load archives
        where_clause = ""
        params = []
        if query:
            where_clause += " AND a.title LIKE %s"
            params.append(f'%{sanitize_input(query)}%')
        if category_id:
            where_clause += " AND ac.category_id = %s"
            params.append(category_id)
        
        cursor.execute(f"""
            SELECT 
                a.id, 
                a.title, 
                a.description, 
                a.file_name, 
                a.file_type, 
                a.file_size, 
                a.is_public, 
                a.created_at, 
                u.username AS uploader, 
                c.name AS category_name
            FROM archives a
            JOIN archive_category ac ON a.id = ac.archive_id
            JOIN categories c ON ac.category_id = c.id
            LEFT JOIN user u ON a.user_id = u.id
            WHERE 1=1 {where_clause}
            ORDER BY a.created_at DESC
        """, params)
        archives = cursor.fetchall()
        
        # Format file_size and created_at
        for archive in archives:
            archive['file_size_formatted'] = format_file_size(archive['file_size'])
            archive['created_at'] = archive['created_at'].strftime('%d %b %Y')
        
        # Log activity
        log_activity(
            user_id=current_user.id,
            action='view_admin_archive_management',
            ip_address=ip_address,
            user_agent=user_agent,
            description=f"Admin {current_user.username} melihat halaman manajemen arsip",
            details={'archive_count': len(archives), 'query': query, 'category_id': category_id}
        )
        
        return render_template(
            'admin_archive_management.html',
            archives=archives,
            categories=categories,
            title='Archive Management',
            csrf_token=generate_csrf(),
            current_year=datetime.now(pytz.timezone('Asia/Jakarta')).year,
            query=query,
            category_id=category_id
        )
        
    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] MySQL error: {e}", exc_info=True)
        log_system_error(
            module="Admin Archive Management",
            message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'query': query, 'category_id': category_id}
        )
        flash(f'Terjadi kesalahan database (ID: {error_id}).', 'danger')
        return render_template(
            'admin_archive_management.html',
            archives=[],
            categories=[],
            title='Archive Management',
            current_year=datetime.now(pytz.timezone('Asia/Jakarta')).year,
            query=query,
            category_id=category_id
        )
        
    except Exception as e:
        logger.error(f"[{error_id}] Kesalahan tak terduga: {e}", exc_info=True)
        log_system_error(
            module="Admin Archive Management",
            message=f"Kesalahan tak terduga [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'query': query, 'category_id': category_id}
        )
        flash(f'Terjadi kesalahan sistem (ID: {error_id}).', 'danger')
        return render_template(
            'admin_archive_management.html',
            archives=[],
            categories=[],
            title='Archive Management',
            current_year=datetime.now(pytz.timezone('Asia/Jakarta')).year,
            query=query,
            category_id=category_id
        )
        
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()
# ==================== SYSTEM SETTINGS ====================
@app.route('/admin/settings', methods=['GET', 'POST'])
@app.route('/admin/system-settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_system_settings():
    """Admin System Settings Route"""
    error_id = str(uuid.uuid4())
    ip_address = request.remote_addr or 'unknown'
    user_agent = request.user_agent.string or 'unknown'
    current_time = datetime.now(pytz.timezone('Asia/Jakarta'))
    search_query = request.args.get('q', '').strip().lower()
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error(f"[{error_id}] Admin system settings: Database connection failed")
            log_system_error(
                module="Admin System Settings",
                message=f"Database connection failed [{error_id}]",
                ip_address=ip_address,
                user_id=current_user.id,
                details={'search_query': search_query}
            )
            flash('Gagal terhubung ke database.', 'danger')
            return render_template(
                'admin_system_settings.html',
                settings=[],
                search_query=search_query,
                title='Pengaturan Sistem',
                csrf_token=generate_csrf(),
                current_year=current_time.year
            )
        
        cursor = conn.cursor(dictionary=True)
        
        # Handle POST requests (create, update, delete)
        if request.method == 'POST':
            csrf_token = request.form.get('csrf_token')
            if not csrf_token or csrf_token != generate_csrf():
                flash('CSRF token tidak valid.', 'danger')
                return redirect(url_for('admin_system_settings'))
            
            action = request.form.get('action')
            
            if action == 'delete':
                setting_id = request.form.get('setting_id')
                if not setting_id or not setting_id.isdigit():
                    flash('ID pengaturan tidak valid.', 'danger')
                    return redirect(url_for('admin_system_settings'))
                
                cursor.execute("SELECT id, `key` FROM system_settings WHERE id = %s", (setting_id,))
                setting = cursor.fetchone()
                if not setting:
                    flash('Pengaturan tidak ditemukan.', 'danger')
                    return redirect(url_for('admin_system_settings'))
                
                try:
                    cursor.execute("DELETE FROM system_settings WHERE id = %s", (setting_id,))
                    conn.commit()
                    
                    log_activity(
                        user_id=current_user.id,
                        action='delete_system_setting',
                        ip_address=ip_address,
                        user_agent=user_agent,
                        description=f"Admin {current_user.username} menghapus pengaturan: {setting['key']}",
                        details={'setting_id': int(setting_id), 'key': setting['key']}
                    )
                    flash(f"Pengaturan '{setting['key']}' berhasil dihapus!", 'success')
                except mysql.connector.Error as e:
                    conn.rollback()
                    logger.error(f"[{error_id}] Gagal menghapus pengaturan: {e}")
                    flash(f'Gagal menghapus pengaturan (ID: {error_id}).', 'danger')
                return redirect(url_for('admin_system_settings'))
            
            # Handle create or update
            setting_key = request.form.get('key', '').strip()
            setting_value = request.form.get('value', '').strip()
            setting_description = request.form.get('description', '').strip() or None
            setting_id = request.form.get('setting_id') if action == 'update' else None
            
            # Validate inputs
            if not setting_key or len(setting_key) > 100 or not re.match(r'^[a-zA-Z0-9_]+$', setting_key):
                flash('Kunci harus 1-100 karakter, hanya huruf, angka, atau underscore.', 'danger')
                return redirect(url_for('admin_system_settings'))
            
            if not setting_value:
                flash('Nilai pengaturan diperlukan.', 'danger')
                return redirect(url_for('admin_system_settings'))
            
            try:
                if action == 'update' and setting_id:
                    cursor.execute("SELECT id, `key` FROM system_settings WHERE id = %s", (setting_id,))
                    existing = cursor.fetchone()
                    if not existing:
                        flash('Pengaturan tidak ditemukan.', 'danger')
                        return redirect(url_for('admin_system_settings'))
                    
                    cursor.execute("SELECT id FROM system_settings WHERE `key` = %s AND id != %s", (setting_key, setting_id))
                    if cursor.fetchone():
                        flash(f"Kunci '{setting_key}' sudah digunakan.", 'danger')
                        return redirect(url_for('admin_system_settings'))
                    
                    cursor.execute("""
                        UPDATE system_settings 
                        SET `key` = %s, value = %s, description = %s, updated_at = %s 
                        WHERE id = %s
                    """, (setting_key, setting_value, setting_description, current_time, setting_id))
                    action_msg = 'diperbarui'
                    log_details = {'setting_id': int(setting_id), 'key': setting_key, 'value': setting_value, 'action': 'update'}
                else:
                    cursor.execute("SELECT id FROM system_settings WHERE `key` = %s", (setting_key,))
                    if cursor.fetchone():
                        flash(f"Kunci '{setting_key}' sudah digunakan.", 'danger')
                        return redirect(url_for('admin_system_settings'))
                    
                    cursor.execute("""
                        INSERT INTO system_settings (`key`, value, description, created_at)
                        VALUES (%s, %s, %s, %s)
                    """, (setting_key, setting_value, setting_description, current_time))
                    action_msg = 'dibuat'
                    log_details = {'key': setting_key, 'value': setting_value, 'action': 'create'}
                
                conn.commit()
                
                log_activity(
                    user_id=current_user.id,
                    action='modify_system_setting',
                    ip_address=ip_address,
                    user_agent=user_agent,
                    description=f"Admin {current_user.username} {action_msg} pengaturan: {setting_key}",
                    details=log_details
                )
                
                flash(f"Pengaturan '{setting_key}' berhasil {action_msg}!", 'success')
            except mysql.connector.Error as e:
                conn.rollback()
                logger.error(f"[{error_id}] Gagal membuat/memperbarui pengaturan: {e}")
                flash(f'Gagal membuat/memperbarui pengaturan (ID: {error_id}).', 'danger')
            return redirect(url_for('admin_system_settings'))
        
        # GET request: Load settings
        query = """
            SELECT id, `key`, value, description, created_at, updated_at
            FROM system_settings
            WHERE %s = '' OR 
                  LOWER(`key`) LIKE %s OR 
                  LOWER(description) LIKE %s
            ORDER BY `key` ASC
        """
        cursor.execute(query, (
            search_query,
            f'%{search_query}%',
            f'%{search_query}%'
        ))
        settings = cursor.fetchall()
        
        log_activity(
            user_id=current_user.id,
            action='view_admin_system_settings',
            ip_address=ip_address,
            user_agent=user_agent,
            description=f"Admin {current_user.username} melihat halaman pengaturan sistem",
            details={'settings_count': len(settings), 'search_query': search_query}
        )
        
        return render_template(
            'admin_system_settings.html',
            settings=settings,
            search_query=search_query,
            title='Pengaturan Sistem',
            csrf_token=generate_csrf(),
            current_year=current_time.year
        )
        
    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] MySQL error: {e}")
        log_system_error(
            module="Admin System Settings",
            message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'search_query': search_query}
        )
        flash(f'Terjadi kesalahan database (ID: {error_id}).', 'danger')
        return render_template(
            'admin_system_settings.html',
            settings=[],
            search_query=search_query,
            title='Pengaturan Sistem',
            csrf_token=generate_csrf(),
            current_year=current_time.year
        )
        
    except Exception as e:
        logger.error(f"[{error_id}] Kesalahan tak terduga: {e}")
        log_system_error(
            module="Admin System Settings",
            message=f"Kesalahan tak terduga [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'search_query': search_query}
        )
        flash(f'Terjadi kesalahan sistem (ID: {error_id}).', 'danger')
        return render_template(
            'admin_system_settings.html',
            settings=[],
            search_query=search_query,
            title='Pengaturan Sistem',
            csrf_token=generate_csrf(),
            current_year=current_time.year
        )
        
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/admin/dashboard-stats', methods=['GET'])
@login_required
@admin_required
def api_admin_dashboard_stats():
    """API endpoint to retrieve dashboard statistics"""
    error_id = str(uuid.uuid4())
    ip_address = request.remote_addr or 'unknown'
    user_agent = request.user_agent.string or 'unknown'
    current_time = datetime.now(pytz.timezone('Asia/Jakarta'))
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error(f"[{error_id}] API dashboard stats: Database connection failed")
            log_system_error(
                module="API Dashboard Stats",
                message=f"Database connection failed [{error_id}]",
                ip_address=ip_address,
                user_id=current_user.id,
                details={}
            )
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        stats = {}
        
        # Total active users
        cursor.execute("SELECT COUNT(*) as count FROM user WHERE is_active = 1")
        stats['totalUsers'] = cursor.fetchone()['count']
        
        # Total archives
        cursor.execute("SELECT COUNT(*) as count FROM archives")
        stats['totalArchives'] = cursor.fetchone()['count']
        
        # System logs in the last 7 days
        cursor.execute("SELECT COUNT(*) as count FROM system_logs WHERE created_at >= DATE_SUB(%s, INTERVAL 7 DAY)", (current_time,))
        stats['totalLogs'] = cursor.fetchone()['count']
        
        # Unread notifications for the current user
        cursor.execute("SELECT COUNT(*) as count FROM notifications WHERE user_id = %s AND is_read = 0", (current_user.id,))
        stats['totalNotifications'] = cursor.fetchone()['count']
        
        # Log the API call
        log_activity(
            user_id=current_user.id,
            action='view_dashboard_stats',
            ip_address=ip_address,
            user_agent=user_agent,
            description=f"Admin {current_user.username} retrieved dashboard statistics",
            details={'stats': stats}
        )
        
        return jsonify(stats)
        
    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] MySQL error in API dashboard stats: {e}")
        log_system_error(
            module="API Dashboard Stats",
            message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={}
        )
        return jsonify({'error': 'Database error occurred'}), 500
        
    except Exception as e:
        logger.error(f"[{error_id}] Unexpected error in API dashboard stats: {e}")
        log_system_error(
            module="API Dashboard Stats",
            message=f"Unexpected error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={}
        )
        return jsonify({'error': 'Internal server error'}), 500
        
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/admin/recent-logs', methods=['GET'])
@login_required
@admin_required
def api_admin_recent_logs():
    """API endpoint to retrieve recent system logs with pagination"""
    error_id = str(uuid.uuid4())
    ip_address = request.remote_addr or 'unknown'
    user_agent = request.user_agent.string or 'unknown'
    
    # Pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    if per_page > 100:
        per_page = 100  # Limit maximum records per page
    offset = (page - 1) * per_page
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error(f"[{error_id}] API recent logs: Database connection failed")
            log_system_error(
                module="API Recent Logs",
                message=f"Database connection failed [{error_id}]",
                ip_address=ip_address,
                user_id=current_user.id,
                details={'page': page, 'per_page': per_page}
            )
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Fetch recent logs
        query = """
            SELECT id, level, module, message, user_id, ip_address,
                   DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i:%%s') as created_at
            FROM system_logs
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """
        cursor.execute(query, (per_page, offset))
        logs = cursor.fetchall()
        
        # Get total count for pagination metadata
        cursor.execute("SELECT COUNT(*) as count FROM system_logs")
        total_logs = cursor.fetchone()['count']
        
        # Log the API call
        log_activity(
            user_id=current_user.id,
            action='view_recent_logs',
            ip_address=ip_address,
            user_agent=user_agent,
            description=f"Admin {current_user.username} retrieved recent system logs",
            details={'page': page, 'per_page': per_page, 'total_logs': total_logs, 'returned_logs': len(logs)}
        )
        
        return jsonify({
            'logs': logs,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_logs,
                'pages': (total_logs + per_page - 1) // per_page
            }
        })
        
    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] MySQL error in API recent logs: {e}")
        log_system_error(
            module="API Recent Logs",
            message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'page': page, 'per_page': per_page}
        )
        return jsonify({'error': 'Database error occurred'}), 500
        
    except Exception as e:
        logger.error(f"[{error_id}] Unexpected error in API recent logs: {e}")
        log_system_error(
            module="API Recent Logs",
            message=f"Unexpected error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'page': page, 'per_page': per_page}
        )
        return jsonify({'error': 'Internal server error'}), 500
        
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/admin/recent-notifications', methods=['GET'])
@login_required
@admin_required
def api_admin_recent_notifications():
    """API endpoint to retrieve recent notifications with pagination"""
    error_id = str(uuid.uuid4())
    ip_address = request.remote_addr or 'unknown'
    user_agent = request.user_agent.string or 'unknown'
    
    # Pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    if per_page > 100:
        per_page = 100  # Limit maximum records per page
    offset = (page - 1) * per_page
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error(f"[{error_id}] API recent notifications: Database connection failed")
            log_system_error(
                module="API Recent Notifications",
                message=f"Database connection failed [{error_id}]",
                ip_address=ip_address,
                user_id=current_user.id,
                details={'page': page, 'per_page': per_page}
            )
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Fetch recent notifications for the current user
        query = """
            SELECT id, user_id, message, is_read, related_url,
                   DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i:%%s') as created_at,
                   DATE_FORMAT(read_at, '%%Y-%%m-%%d %%H:%%i:%%s') as read_at
            FROM notifications
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """
        cursor.execute(query, (current_user.id, per_page, offset))
        notifications = cursor.fetchall()
        
        # Get total count for pagination metadata
        cursor.execute("SELECT COUNT(*) as count FROM notifications WHERE user_id = %s", (current_user.id,))
        total_notifications = cursor.fetchone()['count']
        
        # Log the API call
        log_activity(
            user_id=current_user.id,
            action='view_recent_notifications',
            ip_address=ip_address,
            user_agent=user_agent,
            description=f"Admin {current_user.username} retrieved recent notifications",
            details={'page': page, 'per_page': per_page, 'total_notifications': total_notifications, 'returned_notifications': len(notifications)}
        )
        
        return jsonify({
            'notifications': notifications,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_notifications,
                'pages': (total_notifications + per_page - 1) // per_page
            }
        })
        
    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] MySQL error in API recent notifications: {e}")
        log_system_error(
            module="API Recent Notifications",
            message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'page': page, 'per_page': per_page}
        )
        return jsonify({'error': 'Database error occurred'}), 500
        
    except Exception as e:
        logger.error(f"[{error_id}] Unexpected error in API recent notifications: {e}")
        log_system_error(
            module="API Recent Notifications",
            message=f"Unexpected error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'page': page, 'per_page': per_page}
        )
        return jsonify({'error': 'Internal server error'}), 500
        
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/notifications/<int:notification_id>/mark-read', methods=['PUT'])
@login_required
@admin_required
def api_mark_notification_read(notification_id):
    """API endpoint to mark a notification as read"""
    error_id = str(uuid.uuid4())
    ip_address = request.remote_addr or 'unknown'
    user_agent = request.user_agent.string or 'unknown'
    current_time = datetime.now(pytz.timezone('Asia/Jakarta'))
    
    conn = None
    cursor = None
    
    try:
        # Verify CSRF token for PUT request
        csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        if not csrf_token or csrf_token != generate_csrf():
            return jsonify({'error': 'Invalid CSRF token'}), 403
        
        conn = get_db_connection()
        if not conn or not conn.is_connected():
            logger.error(f"[{error_id}] API mark notification read: Database connection failed")
            log_system_error(
                module="API Mark Notification Read",
                message=f"Database connection failed [{error_id}]",
                ip_address=ip_address,
                user_id=current_user.id,
                details={'notification_id': notification_id}
            )
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Check if notification exists and belongs to the user
        cursor.execute("SELECT id, user_id FROM notifications WHERE id = %s AND user_id = %s", (notification_id, current_user.id))
        notification = cursor.fetchone()
        if not notification:
            return jsonify({'error': 'Notification not found or unauthorized'}), 404
        
        # Update notification
        cursor.execute("""
            UPDATE notifications 
            SET is_read = 1, read_at = %s 
            WHERE id = %s
        """, (current_time, notification_id))
        
        conn.commit()
        
        # Log the action
        log_activity(
            user_id=current_user.id,
            action='mark_notification_read',
            ip_address=ip_address,
            user_agent=user_agent,
            description=f"Admin {current_user.username} marked notification {notification_id} as read",
            details={'notification_id': notification_id}
        )
        
        return jsonify({'success': True, 'message': 'Notification marked as read'})
        
    except mysql.connector.Error as e:
        logger.error(f"[{error_id}] MySQL error in API mark notification read: {e}")
        log_system_error(
            module="API Mark Notification Read",
            message=f"MySQL error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'notification_id': notification_id}
        )
        return jsonify({'error': 'Database error occurred'}), 500
        
    except Exception as e:
        logger.error(f"[{error_id}] Unexpected error in API mark notification read: {e}")
        log_system_error(
            module="API Mark Notification Read",
            message=f"Unexpected error [{error_id}]: {str(e)}",
            ip_address=ip_address,
            user_id=current_user.id,
            details={'notification_id': notification_id}
        )
        return jsonify({'error': 'Internal server error'}), 500
        
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


# Error Handlers
@app.errorhandler(400)
def bad_request(e):
    log_system_error("System", f"Bad request: {str(e)}")
    return render_template('errors/400.html', title='Bad Request'), 400

@app.errorhandler(403)
def forbidden(e):
    log_system_error("System", f"Forbidden: {str(e)}")
    return render_template('errors/403.html', title='Forbidden'), 403

@app.errorhandler(404)
def not_found(e):
    log_system_error("System", f"Not found: {str(e)}")
    return render_template('errors/404.html', title='Not Found'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {str(e)}")
    log_system_error("System", f"Internal server error: {str(e)}")
    return render_template('errors/500.html', title='Internal Server Error'), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

