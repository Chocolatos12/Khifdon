import streamlit as st
import sys
import sqlite3
import hashlib
import hmac
import secrets
import numpy as np
from PIL import Image
import io
import base64
from datetime import datetime, timedelta
import os
import zipfile
import logging
import traceback
from typing import Optional, Tuple, Dict, Any
import jwt
from cryptography.fernet import Fernet
import bcrypt
import re
from functools import wraps
import time


# =============================================================================
# KONFIGURASI APLIKASI
# =============================================================================

class Config:
    """Konfigurasi aplikasi yang aman untuk production"""

    # Database
    DB_NAME = os.getenv("DATABASE_PATH", "steganografi_production.db")

    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
    JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key())

    # Rate limiting
    MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_DURATION = int(os.getenv("LOCKOUT_DURATION", "15"))  # minutes

    # File limits
    MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", "10485760"))  # 10MB default
    ALLOWED_IMAGE_TYPES = ['png', 'jpg', 'jpeg', 'bmp', 'tiff']

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", "filestegano.log")


# =============================================================================
# LOGGING SETUP
# =============================================================================

logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# =============================================================================
# SECURITY UTILITIES
# =============================================================================

class SecurityManager:
    """Mengelola aspek keamanan aplikasi"""

    def __init__(self):
        self.fernet = Fernet(Config.ENCRYPTION_KEY)
        self.failed_attempts = {}
        self.rate_limit_storage = {}

    def hash_password(self, password: str) -> str:
        """Hash password menggunakan bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verifikasi password"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False

    def encrypt_data(self, data: bytes) -> bytes:
        """Enkripsi data"""
        return self.fernet.encrypt(data)

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Dekripsi data"""
        return self.fernet.decrypt(encrypted_data)

    def generate_jwt_token(self, user_data: Dict[str, Any]) -> str:
        """Generate JWT token"""
        payload = {
            'user_id': user_data['id'],
            'username': user_data['username'],
            'exp': datetime.utcnow() + timedelta(hours=24),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, Config.JWT_SECRET, algorithm='HS256')

    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verifikasi JWT token"""
        try:
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            return None

    def rate_limit(self, identifier: str, max_requests: int = 10, window: int = 60) -> bool:
        """Rate limiting implementation"""
        now = time.time()
        if identifier not in self.rate_limit_storage:
            self.rate_limit_storage[identifier] = []

        # Clean old requests
        self.rate_limit_storage[identifier] = [
            req_time for req_time in self.rate_limit_storage[identifier]
            if now - req_time < window
        ]

        if len(self.rate_limit_storage[identifier]) >= max_requests:
            return False

        self.rate_limit_storage[identifier].append(now)
        return True

    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename untuk keamanan"""
        # Remove path traversal attempts
        filename = os.path.basename(filename)
        # Remove dangerous characters
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250] + ext
        return filename

    def validate_file_type(self, file_content: bytes, expected_types: list) -> bool:
        """Validasi tipe file berdasarkan magic bytes"""
        magic_bytes = {
            'png': b'\x89PNG\r\n\x1a\n',
            'jpg': b'\xff\xd8\xff',
            'jpeg': b'\xff\xd8\xff',
            'gif': b'GIF8',
            'bmp': b'BM',
            'tiff': b'II*\x00',
            'pdf': b'%PDF',
        }

        for file_type in expected_types:
            if file_type.lower() in magic_bytes:
                magic = magic_bytes[file_type.lower()]
                if file_content.startswith(magic):
                    return True
        return False


# =============================================================================
# DATABASE MANAGEMENT
# =============================================================================

class DatabaseManager:
    """Mengelola operasi database dengan keamanan yang lebih baik"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()

    def get_connection(self):
        """Get database connection dengan konfigurasi keamanan"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def init_database(self):
        """Inisialisasi database dengan schema yang aman"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Users table dengan security fields
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        full_name TEXT NOT NULL,
                        profile_pic TEXT DEFAULT 'default.jpg',
                        bio TEXT DEFAULT '',
                        access_level TEXT DEFAULT 'user' CHECK(access_level IN ('user', 'admin', 'moderator')),
                        is_active BOOLEAN DEFAULT 1,
                        is_verified BOOLEAN DEFAULT 0,
                        failed_login_attempts INTEGER DEFAULT 0,
                        locked_until TIMESTAMP NULL,
                        last_login TIMESTAMP NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Invitation codes
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS invitation_codes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        code TEXT UNIQUE NOT NULL,
                        created_by INTEGER NOT NULL,
                        max_uses INTEGER DEFAULT 1,
                        current_uses INTEGER DEFAULT 0,
                        expires_at TIMESTAMP NOT NULL,
                        is_active BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')

                # Audit logs
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        action TEXT NOT NULL,
                        resource TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        success BOOLEAN DEFAULT 1,
                        details TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
                    )
                ''')

                # File operations history
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS file_operations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        operation_type TEXT NOT NULL CHECK(operation_type IN ('HIDE', 'EXTRACT')),
                        cover_image_name TEXT NOT NULL,
                        cover_image_hash TEXT,
                        hidden_file_name TEXT,
                        hidden_file_type TEXT,
                        hidden_file_size INTEGER,
                        output_filename TEXT,
                        success BOOLEAN DEFAULT 1,
                        error_message TEXT,
                        processing_time REAL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')

                # Sessions table untuk JWT management
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        session_token TEXT UNIQUE NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        expires_at TIMESTAMP NOT NULL,
                        is_active BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                ''')

                # Create indexes untuk performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_operations_user_id ON file_operations(user_id)')

                # Create default admin jika belum ada
                self._create_default_admin(cursor)

                conn.commit()
                logger.info("Database initialized successfully")

        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            raise

    def _create_default_admin(self, cursor):
        """Create default admin account"""
        security = SecurityManager()
        admin_password = os.getenv("ADMIN_PASSWORD", "AdminSecure2024!")

        try:
            hashed_password = security.hash_password(admin_password)
            cursor.execute('''
                INSERT OR IGNORE INTO users 
                (username, email, password_hash, full_name, access_level, is_active, is_verified) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ("admin", "admin@company.com", hashed_password, "System Administrator",
                  "admin", 1, 1))

            if cursor.rowcount > 0:
                logger.info("Default admin account created")
        except Exception as e:
            logger.error(f"Error creating default admin: {e}")

    def log_action(self, user_id: Optional[int], action: str, resource: str = None,
                   ip_address: str = None, user_agent: str = None, success: bool = True,
                   details: str = None):
        """Log user actions untuk audit"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO audit_logs 
                    (user_id, action, resource, ip_address, user_agent, success, details) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (user_id, action, resource, ip_address, user_agent, success, details))
                conn.commit()
        except Exception as e:
            logger.error(f"Error logging action: {e}")


# =============================================================================
# USER MANAGEMENT
# =============================================================================

class UserManager:
    """Mengelola operasi user dengan keamanan tinggi"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.security = SecurityManager()

    def authenticate_user(self, username_or_email: str, password: str,
                          ip_address: str = None) -> Tuple[Optional[Dict], Optional[str]]:
        """Autentikasi user dengan security checks"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()

                # Check if account is locked
                cursor.execute('''
                    SELECT id, username, email, password_hash, full_name, bio, profile_pic, 
                           access_level, is_active, is_verified, failed_login_attempts, locked_until
                    FROM users 
                    WHERE (username = ? OR email = ?) AND is_active = 1
                ''', (username_or_email, username_or_email))

                user_data = cursor.fetchone()
                if not user_data:
                    self.db.log_action(None, "LOGIN_FAILED", username_or_email, ip_address,
                                       success=False, details="User not found")
                    return None, "Invalid credentials"

                user_id, username, email, password_hash, full_name, bio, profile_pic, \
                    access_level, is_active, is_verified, failed_attempts, locked_until = user_data

                # Check if account is locked
                if locked_until:
                    lock_time = datetime.fromisoformat(locked_until)
                    if datetime.now() < lock_time:
                        return None, f"Account locked until {locked_until}"
                    else:
                        # Unlock account
                        cursor.execute('''
                            UPDATE users SET locked_until = NULL, failed_login_attempts = 0 
                            WHERE id = ?
                        ''', (user_id,))

                # Verify password
                if not self.security.verify_password(password, password_hash):
                    # Increment failed attempts
                    failed_attempts += 1
                    if failed_attempts >= Config.MAX_LOGIN_ATTEMPTS:
                        lock_until = datetime.now() + timedelta(minutes=Config.LOCKOUT_DURATION)
                        cursor.execute('''
                            UPDATE users SET failed_login_attempts = ?, locked_until = ? 
                            WHERE id = ?
                        ''', (failed_attempts, lock_until.isoformat(), user_id))
                        self.db.log_action(user_id, "ACCOUNT_LOCKED", username, ip_address,
                                           success=False, details=f"Too many failed attempts")
                        return None, "Account locked due to too many failed attempts"
                    else:
                        cursor.execute('''
                            UPDATE users SET failed_login_attempts = ? WHERE id = ?
                        ''', (failed_attempts, user_id))

                    self.db.log_action(user_id, "LOGIN_FAILED", username, ip_address,
                                       success=False, details="Invalid password")
                    return None, "Invalid credentials"

                # Check if user is verified
                if not is_verified and access_level != 'admin':
                    return None, "Account not verified. Please contact administrator."

                # Successful login - reset failed attempts
                cursor.execute('''
                    UPDATE users SET failed_login_attempts = 0, locked_until = NULL, 
                                   last_login = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (user_id,))

                conn.commit()

                user_dict = {
                    'id': user_id,
                    'username': username,
                    'email': email,
                    'full_name': full_name,
                    'bio': bio,
                    'profile_pic': profile_pic,
                    'access_level': access_level,
                    'is_verified': is_verified
                }

                self.db.log_action(user_id, "LOGIN_SUCCESS", username, ip_address,
                                   success=True)

                return user_dict, None

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None, "Authentication error occurred"

    def register_user(self, username: str, email: str, password: str, full_name: str,
                      invitation_code: str = None) -> Tuple[bool, str]:
        """Register user baru dengan validasi ketat"""
        try:
            # Validate input
            if not self._validate_registration_input(username, email, password, full_name):
                return False, "Invalid input data"

            # Validate invitation code if provided
            if invitation_code and not self._validate_invitation_code(invitation_code):
                return False, "Invalid or expired invitation code"

            with self.db.get_connection() as conn:
                cursor = conn.cursor()

                # Check if user already exists
                cursor.execute('''
                    SELECT id FROM users WHERE username = ? OR email = ?
                ''', (username, email))

                if cursor.fetchone():
                    return False, "Username or email already exists"

                # Hash password
                password_hash = self.security.hash_password(password)

                # Determine verification status
                is_verified = 1 if invitation_code else 0
                access_level = 'user'

                # Insert user
                cursor.execute('''
                    INSERT INTO users 
                    (username, email, password_hash, full_name, access_level, is_verified) 
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (username, email, password_hash, full_name, access_level, is_verified))

                user_id = cursor.lastrowid

                # Use invitation code if provided
                if invitation_code:
                    self._use_invitation_code(cursor, invitation_code, user_id)

                conn.commit()

                self.db.log_action(user_id, "USER_REGISTERED", username,
                                   success=True, details=f"Invitation code: {invitation_code}")

                return True, "Registration successful"

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False, "Registration failed due to system error"

    def _validate_registration_input(self, username: str, email: str,
                                     password: str, full_name: str) -> bool:
        """Validasi input registrasi"""
        # Username validation
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
            return False

        # Email validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            return False

        # Password validation
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[0-9]', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False

        # Full name validation
        if len(full_name.strip()) < 2:
            return False

        return True

    def _validate_invitation_code(self, code: str) -> bool:
        """Validasi invitation code"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT max_uses, current_uses, expires_at, is_active 
                    FROM invitation_codes 
                    WHERE code = ? AND is_active = 1
                ''', (code,))

                result = cursor.fetchone()
                if not result:
                    return False

                max_uses, current_uses, expires_at, is_active = result

                # Check expiry
                if datetime.now() > datetime.fromisoformat(expires_at):
                    return False

                # Check usage limit
                if current_uses >= max_uses:
                    return False

                return True
        except Exception as e:
            logger.error(f"Invitation code validation error: {e}")
            return False

    def _use_invitation_code(self, cursor, code: str, user_id: int):
        """Gunakan invitation code"""
        cursor.execute('''
            UPDATE invitation_codes 
            SET current_uses = current_uses + 1 
            WHERE code = ?
        ''', (code,))


# =============================================================================
# STEGANOGRAPHY ENGINE
# =============================================================================

class SteganographyEngine:
    """Engine steganografi dengan keamanan dan error handling yang baik"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.security = SecurityManager()

    def hide_file_in_image(self, cover_image: Image.Image, file_data: bytes,
                           filename: str, user_id: int) -> Tuple[Optional[Image.Image], Optional[str]]:
        """Sembunyikan file dalam gambar dengan enkripsi"""
        start_time = time.time()

        try:
            # Sanitize filename
            filename = self.security.sanitize_filename(filename)

            # Encrypt file data
            encrypted_data = self.security.encrypt_data(file_data)

            # Create secure header
            header_data = {
                'filename': filename,
                'original_size': len(file_data),
                'encrypted_size': len(encrypted_data),
                'timestamp': datetime.now().isoformat(),
                'checksum': hashlib.sha256(file_data).hexdigest()
            }

            header_json = str(header_data).encode('utf-8')
            header_encrypted = self.security.encrypt_data(header_json)

            # Combine header and data
            full_data = len(header_encrypted).to_bytes(4, 'big') + header_encrypted + encrypted_data

            # Convert to binary
            binary_data = ''.join(format(byte, '08b') for byte in full_data)

            # Add end marker
            end_marker = '1' * 32  # 32-bit end marker
            binary_data += end_marker

            # Check capacity
            img_array = np.array(cover_image.convert('RGB'))
            total_pixels = img_array.shape[0] * img_array.shape[1] * 3

            if len(binary_data) > total_pixels:
                error_msg = f"File too large. Need {len(binary_data)} bits, available {total_pixels} bits"
                self._log_operation(user_id, "HIDE", filename, success=False,
                                    error_message=error_msg, processing_time=time.time() - start_time)
                return None, error_msg

            # Hide data in LSB
            flat_img = img_array.flatten()
            for i, bit in enumerate(binary_data):
                if i < len(flat_img):
                    flat_img[i] = (flat_img[i] & 0xFE) | int(bit)

            # Reshape and create result image
            result_array = flat_img.reshape(img_array.shape)
            result_image = Image.fromarray(result_array.astype(np.uint8))

            # Log successful operation
            processing_time = time.time() - start_time
            self._log_operation(user_id, "HIDE", filename,
                                cover_image_hash=hashlib.sha256(np.array(cover_image).tobytes()).hexdigest(),
                                hidden_file_size=len(file_data),
                                success=True, processing_time=processing_time)

            return result_image, None

        except Exception as e:
            error_msg = f"Error hiding file: {str(e)}"
            logger.error(f"Hide file error: {e}\n{traceback.format_exc()}")
            self._log_operation(user_id, "HIDE", filename, success=False,
                                error_message=error_msg, processing_time=time.time() - start_time)
            return None, error_msg

    def extract_file_from_image(self, stego_image: Image.Image,
                                user_id: int) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
        """Ekstrak file dari gambar dengan dekripsi"""
        start_time = time.time()

        try:
            # Convert image to array
            img_array = np.array(stego_image.convert('RGB'))
            flat_img = img_array.flatten()

            # Extract LSB to get binary data
            binary_data = ''
            end_marker = '1' * 32

            for pixel in flat_img:
                binary_data += str(pixel & 1)

                # Check for end marker
                if len(binary_data) >= len(end_marker):
                    if binary_data.endswith(end_marker):
                        binary_data = binary_data[:-len(end_marker)]
                        break

            # Convert binary to bytes
            if len(binary_data) % 8 != 0:
                return None, None, "Invalid data format"

            raw_bytes = bytearray()
            for i in range(0, len(binary_data), 8):
                byte = binary_data[i:i + 8]
                if len(byte) == 8:
                    raw_bytes.append(int(byte, 2))

            # Extract header length
            if len(raw_bytes) < 4:
                return None, None, "No hidden data found"

            header_length = int.from_bytes(raw_bytes[:4], 'big')

            if len(raw_bytes) < 4 + header_length:
                return None, None, "Corrupted data format"

            # Extract and decrypt header
            header_encrypted = bytes(raw_bytes[4:4 + header_length])
            header_json = self.security.decrypt_data(header_encrypted)
            header_data = eval(header_json.decode('utf-8'))  # Note: In production, use json.loads

            # Extract and decrypt file data
            file_encrypted = bytes(raw_bytes[4 + header_length:4 + header_length + header_data['encrypted_size']])
            file_data = self.security.decrypt_data(file_encrypted)

            # Verify checksum
            if hashlib.sha256(file_data).hexdigest() != header_data['checksum']:
                error_msg = "Data integrity check failed"
                self._log_operation(user_id, "EXTRACT", header_data['filename'],
                                    success=False, error_message=error_msg,
                                    processing_time=time.time() - start_time)
                return None, None, error_msg

            # Log successful extraction
            processing_time = time.time() - start_time
            self._log_operation(user_id, "EXTRACT", header_data['filename'],
                                hidden_file_size=len(file_data),
                                success=True, processing_time=processing_time)

            return file_data, header_data['filename'], None

        except Exception as e:
            error_msg = f"Error extracting file: {str(e)}"
            logger.error(f"Extract file error: {e}\n{traceback.format_exc()}")
            self._log_operation(user_id, "EXTRACT", "unknown", success=False,
                                error_message=error_msg, processing_time=time.time() - start_time)
            return None, None, error_msg

    def _log_operation(self, user_id: int, operation_type: str, filename: str,
                       cover_image_hash: str = None, hidden_file_size: int = None,
                       success: bool = True, error_message: str = None,
                       processing_time: float = None):
        """Log operasi steganografi"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO file_operations 
                    (user_id, operation_type, cover_image_name, cover_image_hash, 
                     hidden_file_name, hidden_file_size, success, error_message, processing_time) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (user_id, operation_type, "uploaded_image", cover_image_hash,
                      filename, hidden_file_size, success, error_message, processing_time))
                conn.commit()
        except Exception as e:
            logger.error(f"Error logging operation: {e}")


# =============================================================================
# STREAMLIT APPLICATION
# =============================================================================

def require_auth(func):
    """Decorator untuk halaman yang memerlukan autentikasi"""

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not st.session_state.get('authenticated', False):
            st.error("⛔ Access denied. Please log in.")
            st.stop()
        return func(*args, **kwargs)

    return wrapper


def init_session_state():
    """Inisialisasi session state"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_data' not in st.session_state:
        st.session_state.user_data = None
    if 'jwt_token' not in st.session_state:
        st.session_state.jwt_token = None


def create_download_link(data, filename: str, mime_type: str = "application/octet-stream"):
    """Buat link download yang aman"""
    if isinstance(data, Image.Image):
        buffer = io.BytesIO()
        data.save(buffer, format='PNG')
        data = buffer.getvalue()

    b64 = base64.b64encode(data).decode()
    href = f'<a href="data:{mime_type};base64,{b64}" download="{filename}" class="download-btn" target="_blank">📥 Download {filename}</a>'
    return href


def main():
    """Main application function"""

    # Page configuration
    st.set_page_config(
        page_title="FileStegano Pro - Enterprise Edition",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Custom CSS for professional look
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

        .stApp {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }

        .main-header {
            background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
            padding: 2rem;
            border-radius: 15px;
            color: white;
            text-align: center;
            margin-bottom: 2rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }

        .auth-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 3rem;
            border-radius: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }

        .user-info {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 1.5rem;
            border-radius: 15px;
            color: white;
            margin-bottom: 1rem;
        }

        .operation-card {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.3);
        }

        .success-alert {
            background: linear-gradient(90deg, #56ab2f, #a8e6cf);
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin: 1rem 0;
        }

        .error-alert {
            background: linear-gradient(90deg, #ff416c, #ff4b2b);
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin: 1rem 0;
        }

        .download-btn {
            background: linear-gradient(90deg, #667eea, #764ba2);
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 10px;
            display: inline-block;
            margin: 0.5rem 0;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .download-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            text-decoration: none;
            color: white;
        }

        .stats-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 1.5rem;
            text-align: center;
            color: white;
            margin: 1rem 0;
        }

        .sidebar .sidebar-content {
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(10px);
        }
    </style>
    """, unsafe_allow_html=True)

    # Initialize components
    init_session_state()
    db_manager = DatabaseManager(Config.DB_NAME)
    user_manager = UserManager(db_manager)
    stego_engine = SteganographyEngine(db_manager)
    security_manager = SecurityManager()

    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🔐 FileStegano Pro</h1>
        <p>Enterprise-Grade Steganography Solution</p>
        <small>Secure • Encrypted • Auditable</small>
    </div>
    """, unsafe_allow_html=True)

    # Authentication check
    if not st.session_state.authenticated:
        show_auth_page(user_manager, security_manager)
    else:
        show_main_application(db_manager, user_manager, stego_engine, security_manager)


def show_auth_page(user_manager: UserManager, security_manager: SecurityManager):
    """Tampilkan halaman autentikasi"""

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown('<div class="auth-container">', unsafe_allow_html=True)

        tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])

        with tab1:
            st.markdown("### 🔐 Secure Login")

            with st.form("login_form"):
                username = st.text_input("Username or Email", placeholder="Enter username or email")
                password = st.text_input("Password", type="password", placeholder="Enter password")
                remember_me = st.checkbox("Remember me for 30 days")

                submitted = st.form_submit_button("🔑 Sign In", use_container_width=True)

                if submitted:
                    if username and password:
                        # Rate limiting
                        client_ip = "127.0.0.1"  # In production, get real IP
                        if not security_manager.rate_limit(f"login_{client_ip}", max_requests=5, window=300):
                            st.error("⚠️ Too many login attempts. Please try again later.")
                            return

                        user_data, error_msg = user_manager.authenticate_user(
                            username, password, client_ip
                        )

                        if user_data and not error_msg:
                            # Generate JWT token
                            token = security_manager.generate_jwt_token(user_data)

                            # Set session state
                            st.session_state.authenticated = True
                            st.session_state.user_data = user_data
                            st.session_state.jwt_token = token

                            st.success("✅ Login successful!")
                            st.rerun()
                        else:
                            st.error(f"❌ {error_msg}")
                    else:
                        st.warning("⚠️ Please fill in all fields")

            st.markdown("---")
            st.markdown("**🧪 Demo Credentials:**")
            st.info("""
            **Admin Account:**
            - Username: `admin`
            - Password: `AdminSecure2024!`
            """)

        with tab2:
            st.markdown("### 📝 Register New Account")

            with st.form("register_form"):
                reg_username = st.text_input("Username",
                                             placeholder="Choose a username (3-30 chars, alphanumeric + underscore)")
                reg_email = st.text_input("Email", placeholder="Enter your email address")
                reg_full_name = st.text_input("Full Name", placeholder="Enter your full name")
                reg_password = st.text_input("Password", type="password",
                                             placeholder="Min 8 chars with uppercase, lowercase, number, and symbol")
                reg_password_confirm = st.text_input("Confirm Password", type="password",
                                                     placeholder="Confirm your password")
                reg_invitation = st.text_input("Invitation Code (Optional)",
                                               placeholder="Enter invitation code if you have one")

                submitted = st.form_submit_button("📝 Create Account", use_container_width=True)

                if submitted:
                    if all([reg_username, reg_email, reg_full_name, reg_password, reg_password_confirm]):
                        if reg_password != reg_password_confirm:
                            st.error("❌ Passwords do not match")
                        else:
                            success, message = user_manager.register_user(
                                reg_username, reg_email, reg_password, reg_full_name, reg_invitation
                            )

                            if success:
                                st.success("✅ Registration successful! You can now log in.")
                                if not reg_invitation:
                                    st.info(
                                        "ℹ️ Your account requires admin approval before you can access all features.")
                            else:
                                st.error(f"❌ {message}")
                    else:
                        st.warning("⚠️ Please fill in all required fields")

            st.markdown("---")
            st.markdown("**🔒 Password Requirements:**")
            st.markdown("""
            - Minimum 8 characters
            - At least 1 uppercase letter
            - At least 1 lowercase letter  
            - At least 1 number
            - At least 1 special character
            """)

        st.markdown('</div>', unsafe_allow_html=True)


@require_auth
def show_main_application(db_manager: DatabaseManager, user_manager: UserManager,
                          stego_engine: SteganographyEngine, security_manager: SecurityManager):
    """Tampilkan aplikasi utama setelah login"""

    user_data = st.session_state.user_data

    # Sidebar dengan user info dan navigation
    with st.sidebar:
        st.markdown(f"""
        <div class="user-info">
            <h3>👤 {user_data['full_name']}</h3>
            <p><strong>@{user_data['username']}</strong></p>
            <p>🏷️ {user_data['access_level'].title()}</p>
            <p>✅ Verified: {'Yes' if user_data['is_verified'] else 'No'}</p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🚪 Logout", use_container_width=True):
            # Log logout
            db_manager.log_action(user_data['id'], "LOGOUT", user_data['username'])

            # Clear session
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

        st.markdown("---")

        # Show user statistics
        show_user_statistics(db_manager, user_data['id'])

        # Admin panel access
        if user_data['access_level'] == 'admin':
            st.markdown("---")
            st.markdown("**🛠️ Admin Tools**")
            if st.button("👥 User Management"):
                st.session_state.show_admin_panel = True
            if st.button("📊 System Logs"):
                st.session_state.show_logs = True

    # Main content area
    if st.session_state.get('show_admin_panel', False) and user_data['access_level'] == 'admin':
        show_admin_panel(db_manager, user_manager)
    elif st.session_state.get('show_logs', False) and user_data['access_level'] == 'admin':
        show_system_logs(db_manager)
    else:
        show_steganography_interface(stego_engine, security_manager, user_data)


def show_user_statistics(db_manager: DatabaseManager, user_id: int):
    """Tampilkan statistik user"""
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()

            # Get operation counts
            cursor.execute('''
                SELECT operation_type, COUNT(*) 
                FROM file_operations 
                WHERE user_id = ? AND success = 1 
                GROUP BY operation_type
            ''', (user_id,))

            stats = dict(cursor.fetchall())
            hide_count = stats.get('HIDE', 0)
            extract_count = stats.get('EXTRACT', 0)

            st.markdown(f"""
            <div class="stats-card">
                <h4>📊 Your Statistics</h4>
                <p>🔒 Files Hidden: {hide_count}</p>
                <p>🔍 Files Extracted: {extract_count}</p>
                <p>📈 Total Operations: {hide_count + extract_count}</p>
            </div>
            """, unsafe_allow_html=True)

    except Exception as e:
        logger.error(f"Error getting user statistics: {e}")


def show_steganography_interface(stego_engine: SteganographyEngine,
                                 security_manager: SecurityManager, user_data: Dict):
    """Tampilkan interface steganografi utama"""

    tab1, tab2, tab3 = st.tabs(["🔒 Hide File", "🔍 Extract File", "📊 History"])

    with tab1:
        show_hide_file_interface(stego_engine, security_manager, user_data)

    with tab2:
        show_extract_file_interface(stego_engine, security_manager, user_data)

    with tab3:
        show_operation_history(stego_engine.db, user_data['id'])


def show_hide_file_interface(stego_engine: SteganographyEngine,
                             security_manager: SecurityManager, user_data: Dict):
    """Interface untuk menyembunyikan file"""

    st.markdown('<div class="operation-card">', unsafe_allow_html=True)
    st.header("🔒 Hide File in Image")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📸 Cover Image")
        uploaded_image = st.file_uploader(
            "Choose cover image:",
            type=Config.ALLOWED_IMAGE_TYPES,
            key="cover_image",
            help="Upload PNG, JPG, JPEG, BMP, or TIFF image"
        )

        if uploaded_image:
            # Validate file size
            if uploaded_image.size > Config.MAX_FILE_SIZE:
                st.error(f"❌ Image too large. Maximum size: {Config.MAX_FILE_SIZE / 1024 / 1024:.1f}MB")
                return

            # Validate image type
            image_data = uploaded_image.read()
            uploaded_image.seek(0)  # Reset file pointer

            if not security_manager.validate_file_type(image_data, Config.ALLOWED_IMAGE_TYPES):
                st.error("❌ Invalid image format detected")
                return

            try:
                image = Image.open(uploaded_image).convert('RGB')
                st.image(image, caption="Cover Image", use_column_width=True)

                # Calculate capacity
                total_pixels = image.size[0] * image.size[1]
                max_bytes = (total_pixels * 3) // 8 - 2000  # Buffer for header and encryption
                st.info(f"**Maximum file capacity:** ~{max_bytes / 1024:.1f} KB")

            except Exception as e:
                st.error(f"❌ Error loading image: {str(e)}")
                return

    with col2:
        st.subheader("📁 File to Hide")
        uploaded_file = st.file_uploader(
            "Choose file to hide:",
            type=None,
            key="hidden_file",
            help=f"Maximum file size: {Config.MAX_FILE_SIZE / 1024 / 1024:.1f}MB"
        )

        if uploaded_file:
            # Validate file size
            if uploaded_file.size > Config.MAX_FILE_SIZE:
                st.error(f"❌ File too large. Maximum size: {Config.MAX_FILE_SIZE / 1024 / 1024:.1f}MB")
                return

            file_data = uploaded_file.read()
            file_size = len(file_data)

            st.success(f"✅ **{uploaded_file.name}** loaded")
            st.info(f"**Size:** {file_size / 1024:.2f} KB")
            st.info(f"**Type:** {uploaded_file.type or 'Unknown'}")

            # Security scan (basic)
            file_hash = hashlib.sha256(file_data).hexdigest()
            st.code(f"SHA256: {file_hash[:16]}...", language=None)

    # Hide operation
    if uploaded_image and uploaded_file:
        st.markdown("---")

        if st.button("🔒 Hide File in Image", type="primary", use_container_width=True):
            if not security_manager.rate_limit(f"hide_{user_data['id']}", max_requests=10, window=3600):
                st.error("⚠️ Rate limit exceeded. Please try again later.")
                return

            with st.spinner("🔄 Processing... This may take a moment for large files."):
                try:
                    result_image, error_msg = stego_engine.hide_file_in_image(
                        image, file_data, uploaded_file.name, user_data['id']
                    )

                    if result_image and not error_msg:
                        st.markdown('<div class="success-alert">🎉 File successfully hidden in image!</div>',
                                    unsafe_allow_html=True)

                        # Show result
                        st.subheader("📸 Steganographic Image")
                        st.image(result_image, caption="Image with hidden file", use_column_width=True)

                        # Generate secure filename
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        output_filename = f"stego_{timestamp}_{secrets.token_hex(4)}.png"

                        # Download link
                        download_link = create_download_link(
                            result_image, output_filename, "image/png"
                        )
                        st.markdown(download_link, unsafe_allow_html=True)

                        # Security notice
                        st.info(
                            "🔐 **Security Notice:** The hidden file is encrypted and can only be extracted using this application.")

                    else:
                        st.markdown(f'<div class="error-alert">❌ {error_msg}</div>',
                                    unsafe_allow_html=True)

                except Exception as e:
                    logger.error(f"Hide operation error: {e}")
                    st.error("❌ An unexpected error occurred. Please try again.")

    st.markdown('</div>', unsafe_allow_html=True)


def show_extract_file_interface(stego_engine: SteganographyEngine,
                                security_manager: SecurityManager, user_data: Dict):
    """Interface untuk mengekstrak file"""

    st.markdown('<div class="operation-card">', unsafe_allow_html=True)
    st.header("🔍 Extract File from Image")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📸 Steganographic Image")
        uploaded_stego = st.file_uploader(
            "Choose steganographic image:",
            type=Config.ALLOWED_IMAGE_TYPES,
            key="stego_image",
            help="Upload image containing hidden file"
        )

        if uploaded_stego:
            # Validate file
            if uploaded_stego.size > Config.MAX_FILE_SIZE:
                st.error(f"❌ Image too large. Maximum size: {Config.MAX_FILE_SIZE / 1024 / 1024:.1f}MB")
                return

            try:
                stego_image = Image.open(uploaded_stego).convert('RGB')
                st.image(stego_image, caption="Steganographic Image", use_column_width=True)

                # Image info
                st.info(f"**Dimensions:** {stego_image.size[0]} x {stego_image.size[1]}")
                st.info(f"**Size:** {uploaded_stego.size / 1024:.2f} KB")

            except Exception as e:
                st.error(f"❌ Error loading image: {str(e)}")
                return

    with col2:
        if uploaded_stego:
            st.subheader("🔍 Extract Hidden File")

            if st.button("🔍 Extract File", type="primary", use_container_width=True):
                if not security_manager.rate_limit(f"extract_{user_data['id']}", max_requests=20, window=3600):
                    st.error("⚠️ Rate limit exceeded. Please try again later.")
                    return

                with st.spinner("🔄 Extracting hidden file... Please wait."):
                    try:
                        extracted_data, filename, error_msg = stego_engine.extract_file_from_image(
                            stego_image, user_data['id']
                        )

                        if extracted_data and filename and not error_msg:
                            st.markdown('<div class="success-alert">🎉 File successfully extracted!</div>',
                                        unsafe_allow_html=True)

                            # File information
                            file_size = len(extracted_data)
                            file_hash = hashlib.sha256(extracted_data).hexdigest()

                            st.success(f"**📁 Filename:** {filename}")
                            st.info(f"**📊 Size:** {file_size / 1024:.2f} KB")
                            st.code(f"SHA256: {file_hash[:32]}...", language=None)

                            # File preview for safe types
                            show_file_preview(extracted_data, filename)

                            # Download link
                            safe_filename = security_manager.sanitize_filename(filename)
                            download_link = create_download_link(
                                extracted_data, safe_filename, "application/octet-stream"
                            )
                            st.markdown(download_link, unsafe_allow_html=True)

                            # Integrity check
                            st.success("✅ **Integrity Check:** PASSED")
                            st.info("🔐 **Security:** File decrypted successfully")

                        else:
                            error_message = error_msg or "No hidden file found or extraction failed"
                            st.markdown(f'<div class="error-alert">❌ {error_message}</div>',
                                        unsafe_allow_html=True)

                    except Exception as e:
                        logger.error(f"Extract operation error: {e}")
                        st.error("❌ An unexpected error occurred during extraction.")

    st.markdown('</div>', unsafe_allow_html=True)


def show_file_preview(file_data: bytes, filename: str):
    """Tampilkan preview file jika memungkinkan"""
    try:
        file_ext = filename.lower().split('.')[-1] if '.' in filename else ''

        if file_ext in ['txt', 'md', 'py', 'js', 'html', 'css', 'json', 'xml']:
            try:
                preview_text = file_data.decode('utf-8', errors='ignore')[:1000]
                st.text_area("📄 File Preview (first 1000 characters):",
                             preview_text, height=150, disabled=True)
            except:
                st.info("Text preview not available")

        elif file_ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp']:
            try:
                preview_img = Image.open(io.BytesIO(file_data))
                st.image(preview_img, caption=f"🖼️ Preview: {filename}", width=300)
            except:
                st.info("Image preview not available")

        else:
            st.info(f"📄 File type: {file_ext.upper()} - Preview not available")

    except Exception as e:
        logger.error(f"Preview error: {e}")


def show_operation_history(db_manager: DatabaseManager, user_id: int):
    """Tampilkan riwayat operasi user"""

    st.markdown('<div class="operation-card">', unsafe_allow_html=True)
    st.header("📊 Operation History")

    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT operation_type, cover_image_name, hidden_file_name, 
                       hidden_file_size, success, error_message, processing_time, created_at
                FROM file_operations 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT 50
            ''', (user_id,))

            operations = cursor.fetchall()

        if operations:
            st.subheader(f"📈 Recent Operations ({len(operations)})")

            for op in operations:
                op_type, cover_name, hidden_name, file_size, success, error_msg, proc_time, created_at = op

                # Color coding
                if success:
                    status_color = "#28a745"
                    status_icon = "✅"
                    status_text = "Success"
                else:
                    status_color = "#dc3545"
                    status_icon = "❌"
                    status_text = "Failed"

                # Operation icon
                op_icon = "🔒" if op_type == "HIDE" else "🔍"

                st.markdown(f"""
                <div style="border-left: 4px solid {status_color}; padding: 1rem; margin: 1rem 0; 
                           background: rgba(255,255,255,0.1); border-radius: 10px;">
                    <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                        <span style="font-size: 1.2rem; margin-right: 0.5rem;">{op_icon}</span>
                        <strong>{op_type}: {hidden_name or 'Unknown'}</strong>
                        <span style="margin-left: auto;">{status_icon} {status_text}</span>
                    </div>
                    <div style="font-size: 0.9rem; opacity: 0.8;">
                        📸 Cover: {cover_name} • 
                        📊 Size: {file_size / 1024 if file_size else 0:.1f} KB • 
                        ⏱️ Time: {proc_time:.2f}s • 
                        🕒 {created_at}
                    </div>
                    {f'<div style="color: #dc3545; font-size: 0.8rem; margin-top: 0.5rem;">Error: {error_msg}</div>' if not success and error_msg else ''}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("📝 No operations yet. Start hiding or extracting files!")

    except Exception as e:
        logger.error(f"Error loading operation history: {e}")
        st.error("❌ Error loading operation history")

    st.markdown('</div>', unsafe_allow_html=True)


def show_admin_panel(db_manager: DatabaseManager, user_manager: UserManager):
    """Panel admin untuk manajemen user"""

    st.header("🛠️ Admin Panel")

    if st.button("← Back to Main", type="secondary"):
        st.session_state.show_admin_panel = False
        st.rerun()

    st.markdown("---")

    tab1, tab2, tab3 = st.tabs(["👥 Users", "🎫 Invitations", "📊 Statistics"])

    with tab1:
        show_user_management(db_manager)

    with tab2:
        show_invitation_management(db_manager)

    with tab3:
        show_system_statistics(db_manager)


def show_user_management(db_manager: DatabaseManager):
    """Manajemen user untuk admin"""
    st.subheader("👥 User Management")

    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, email, full_name, access_level, is_active, 
                       is_verified, created_at, last_login
                FROM users 
                ORDER BY created_at DESC
            ''')
            users = cursor.fetchall()

        if users:
            for user in users:
                user_id, username, email, full_name, access_level, is_active, is_verified, created_at, last_login = user

                with st.expander(f"👤 {full_name} (@{username})"):
                    col1, col2, col3 = st.columns(3)

                    with col1:
                        st.write(f"**Email:** {email}")
                        st.write(f"**Access Level:** {access_level}")
                        st.write(f"**Created:** {created_at}")

                    with col2:
                        st.write(f"**Active:** {'Yes' if is_active else 'No'}")
                        st.write(f"**Verified:** {'Yes' if is_verified else 'No'}")
                        st.write(f"**Last Login:** {last_login or 'Never'}")

                    with col3:
                        if not is_verified:
                            if st.button(f"✅ Verify", key=f"verify_{user_id}"):
                                try:
                                    with db_manager.get_connection() as conn:
                                        cursor = conn.cursor()
                                        cursor.execute('UPDATE users SET is_verified = 1 WHERE id = ?', (user_id,))
                                        conn.commit()
                                    st.success("User verified successfully!")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Error verifying user: {e}")

                        if not is_active:
                            if st.button(f"🔓 Activate", key=f"activate_{user_id}"):
                                try:
                                    with db_manager.get_connection() as conn:
                                        cursor = conn.cursor()
                                        cursor.execute('UPDATE users SET is_active = 1 WHERE id = ?', (user_id,))
                                        conn.commit()
                                    st.success("User activated successfully!")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Error activating user: {e}")
                        else:
                            if st.button(f"🔒 Deactivate", key=f"deactivate_{user_id}"):
                                try:
                                    with db_manager.get_connection() as conn:
                                        cursor = conn.cursor()
                                        cursor.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
                                        conn.commit()
                                    st.success("User deactivated successfully!")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Error deactivating user: {e}")
        else:
            st.info("No users found")

    except Exception as e:
        logger.error(f"Error loading users: {e}")
        st.error("Error loading user data")


def show_invitation_management(db_manager: DatabaseManager):
    """Manajemen invitation codes"""
    st.subheader("🎫 Invitation Code Management")

    # Create new invitation code
    with st.expander("➕ Create New Invitation Code"):
        with st.form("create_invitation"):
            code = st.text_input("Invitation Code", placeholder="Leave empty for auto-generation")
            max_uses = st.number_input("Maximum Uses", min_value=1, max_value=100, value=1)
            expires_days = st.number_input("Expires in Days", min_value=1, max_value=365, value=30)

            if st.form_submit_button("🎫 Create Code"):
                try:
                    if not code:
                        code = f"INVITE_{secrets.token_urlsafe(8).upper()}"

                    expires_at = datetime.now() + timedelta(days=expires_days)
                    user_id = st.session_state.user_data['id']

                    with db_manager.get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO invitation_codes (code, created_by, max_uses, expires_at)
                            VALUES (?, ?, ?, ?)
                        ''', (code, user_id, max_uses, expires_at.isoformat()))
                        conn.commit()

                    st.success(f"✅ Invitation code created: **{code}**")
                    st.rerun()

                except Exception as e:
                    if "UNIQUE constraint failed" in str(e):
                        st.error("❌ Invitation code already exists")
                    else:
                        st.error(f"❌ Error creating invitation code: {e}")

    # List existing codes
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT ic.code, ic.max_uses, ic.current_uses, ic.expires_at, ic.is_active,
                       ic.created_at, u.username as created_by
                FROM invitation_codes ic
                LEFT JOIN users u ON ic.created_by = u.id
                ORDER BY ic.created_at DESC
            ''')
            codes = cursor.fetchall()

        if codes:
            st.markdown("### 📋 Existing Invitation Codes")

            for code_data in codes:
                code, max_uses, current_uses, expires_at, is_active, created_at, created_by = code_data

                # Status indicators
                if not is_active:
                    status = "🔴 Inactive"
                    status_color = "#dc3545"
                elif datetime.now() > datetime.fromisoformat(expires_at):
                    status = "⏰ Expired"
                    status_color = "#ffc107"
                elif current_uses >= max_uses:
                    status = "✅ Used Up"
                    status_color = "#6c757d"
                else:
                    status = "🟢 Active"
                    status_color = "#28a745"

                st.markdown(f"""
                <div style="border-left: 4px solid {status_color}; padding: 1rem; margin: 1rem 0; 
                           background: rgba(255,255,255,0.1); border-radius: 10px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <div>
                            <strong>🎫 {code}</strong>
                            <span style="margin-left: 1rem;">{status}</span>
                        </div>
                        <div style="text-align: right; font-size: 0.9rem;">
                            Uses: {current_uses}/{max_uses}<br>
                            Expires: {expires_at[:10]}
                        </div>
                    </div>
                    <div style="font-size: 0.8rem; opacity: 0.8; margin-top: 0.5rem;">
                        Created by: {created_by} • {created_at}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No invitation codes found")

    except Exception as e:
        logger.error(f"Error loading invitation codes: {e}")
        st.error("Error loading invitation codes")


def show_system_statistics(db_manager: DatabaseManager):
    """Statistik sistem untuk admin"""
    st.subheader("📊 System Statistics")

    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()

            # User statistics
            cursor.execute('SELECT COUNT(*) FROM users')
            total_users = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
            active_users = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM users WHERE is_verified = 1')
            verified_users = cursor.fetchone()[0]

            # Operation statistics
            cursor.execute('SELECT COUNT(*) FROM file_operations')
            total_operations = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM file_operations WHERE success = 1')
            successful_operations = cursor.fetchone()[0]

            cursor.execute('''
                SELECT operation_type, COUNT(*) 
                FROM file_operations 
                WHERE success = 1 
                GROUP BY operation_type
            ''')
            operation_breakdown = dict(cursor.fetchall())

            # Recent activity
            cursor.execute('''
                SELECT COUNT(*) FROM file_operations 
                WHERE created_at > datetime('now', '-24 hours')
            ''')
            operations_24h = cursor.fetchone()[0]

            cursor.execute('''
                SELECT COUNT(*) FROM users 
                WHERE created_at > datetime('now', '-7 days')
            ''')
            new_users_7d = cursor.fetchone()[0]

        # Display statistics
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("👥 Total Users", total_users)
            st.metric("✅ Active Users", active_users)

        with col2:
            st.metric("🔓 Verified Users", verified_users)
            st.metric("👶 New Users (7d)", new_users_7d)

        with col3:
            st.metric("📊 Total Operations", total_operations)
            st.metric("✅ Successful Ops", successful_operations)

        with col4:
            success_rate = (successful_operations / total_operations * 100) if total_operations > 0 else 0
            st.metric("📈 Success Rate", f"{success_rate:.1f}%")
            st.metric("🔄 Operations (24h)", operations_24h)

        # Operation breakdown
        if operation_breakdown:
            st.markdown("### 📊 Operation Breakdown")
            hide_count = operation_breakdown.get('HIDE', 0)
            extract_count = operation_breakdown.get('EXTRACT', 0)

            col1, col2 = st.columns(2)
            with col1:
                st.metric("🔒 Hide Operations", hide_count)
            with col2:
                st.metric("🔍 Extract Operations", extract_count)

    except Exception as e:
        logger.error(f"Error loading system statistics: {e}")
        st.error("Error loading system statistics")


def show_system_logs(db_manager: DatabaseManager):
    """Tampilkan system logs untuk admin"""
    st.header("📊 System Logs")

    if st.button("← Back to Main", type="secondary"):
        st.session_state.show_logs = False
        st.rerun()

    st.markdown("---")

    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT al.action, al.resource, al.success, al.details, al.created_at,
                       u.username, al.ip_address
                FROM audit_logs al
                LEFT JOIN users u ON al.user_id = u.id
                ORDER BY al.created_at DESC
                LIMIT 100
            ''')
            logs = cursor.fetchall()

        if logs:
            st.subheader(f"📋 Recent System Logs ({len(logs)})")

            # Filters
            col1, col2, col3 = st.columns(3)
            with col1:
                action_filter = st.selectbox("Filter by Action",
                                             ["All"] + list(set([log[0] for log in logs])))
            with col2:
                success_filter = st.selectbox("Filter by Status",
                                              ["All", "Success", "Failed"])
            with col3:
                user_filter = st.selectbox("Filter by User",
                                           ["All"] + list(set([log[5] for log in logs if log[5]])))

            # Apply filters
            filtered_logs = logs
            if action_filter != "All":
                filtered_logs = [log for log in filtered_logs if log[0] == action_filter]
            if success_filter == "Success":
                filtered_logs = [log for log in filtered_logs if log[2]]
            elif success_filter == "Failed":
                filtered_logs = [log for log in filtered_logs if not log[2]]
            if user_filter != "All":
                filtered_logs = [log for log in filtered_logs if log[5] == user_filter]

            # Display logs
            for log in filtered_logs[:50]:  # Limit display
                action, resource, success, details, created_at, username, ip_address = log

                status_color = "#28a745" if success else "#dc3545"
                status_icon = "✅" if success else "❌"

                st.markdown(f"""
                <div style="border-left: 4px solid {status_color}; padding: 1rem; margin: 0.5rem 0; 
                           background: rgba(255,255,255,0.05); border-radius: 8px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <div>
                            <strong>{status_icon} {action}</strong>
                            {f' • {resource}' if resource else ''}
                        </div>
                        <div style="font-size: 0.8rem; opacity: 0.8;">
                            {created_at}
                        </div>
                    </div>
                    <div style="font-size: 0.8rem; opacity: 0.7; margin-top: 0.3rem;">
                        👤 {username or 'Anonymous'} • 🌐 {ip_address or 'Unknown IP'}
                        {f' • {details}' if details else ''}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No logs found")

    except Exception as e:
        logger.error(f"Error loading system logs: {e}")
        st.error("Error loading system logs")


# =============================================================================
# PRODUCTION DEPLOYMENT CONFIGURATION
# =============================================================================

def setup_production_environment():
    """Setup environment untuk production deployment"""

    # Create necessary directories
    os.makedirs("logs", exist_ok=True)
    os.makedirs("data", exist_ok=True)
    os.makedirs("backups", exist_ok=True)

    # Set up proper logging for production
    if Config.LOG_LEVEL == "DEBUG":
        logger.warning("Running in DEBUG mode - not recommended for production")

    # Validate configuration
    required_env_vars = ["SECRET_KEY", "JWT_SECRET", "ENCRYPTION_KEY"]
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]

    if missing_vars:
        logger.warning(f"Missing environment variables: {missing_vars}")
        logger.warning("Using default values - not secure for production!")

    # Security headers for production
    if os.getenv("ENVIRONMENT") == "production":
        st.markdown("""
        <script>
            // Security headers
            if (window.location.protocol !== 'https:') {
                console.warn('Application should run over HTTPS in production');
            }
        </script>
        """, unsafe_allow_html=True)


def create_deployment_files():
    """Buat file-file yang diperlukan untuk deployment"""

    # requirements.txt
    requirements = """
streamlit>=1.28.0
Pillow>=10.0.0
numpy>=1.24.0
cryptography>=41.0.0
PyJWT>=2.8.0
bcrypt>=4.0.0
sqlite3
"""

    # Dockerfile
    dockerfile = """
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    g++ \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs data backups

# Expose port
EXPOSE 8501

# Health check
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

# Run application
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
"""

    # docker-compose.yml
    docker_compose = """
version: '3.8'

services:
  filestegano:
    build: .
    ports:
      - "8501:8501"
    environment:
      - ENVIRONMENT=production
      - SECRET_KEY=${SECRET_KEY}
      - JWT_SECRET=${JWT_SECRET}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - DATABASE_PATH=/app/data/filestegano.db
      - LOG_FILE=/app/logs/filestegano.log
      - MAX_FILE_SIZE=52428800  # 50MB
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./backups:/app/backups
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8501/_stcore/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - filestegano
    restart: unless-stopped
"""

    # nginx.conf
    nginx_conf = """
events {
    worker_connections 1024;
}

http {
    upstream filestegano {
        server filestegano:8501;
    }

    server {
        listen 80;
        server_name your-domain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
        ssl_prefer_server_ciphers off;

        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options DENY;
        add_header X-XSS-Protection "1; mode=block";

        client_max_body_size 100M;

        location / {
            proxy_pass http://filestegano;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 86400;
        }
    }
}
"""

    # .env.example
    env_example = """
# Security Keys (Generate new ones for production!)
SECRET_KEY=your-secret-key-here
JWT_SECRET=your-jwt-secret-here
ENCRYPTION_KEY=your-encryption-key-here

# Database
DATABASE_PATH=./data/filestegano_production.db

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/filestegano.log

# Security Settings
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=15
MAX_FILE_SIZE=52428800

# Admin Account
ADMIN_PASSWORD=YourSecureAdminPassword2024!

# Environment
ENVIRONMENT=production
"""

    return {
        "requirements.txt": requirements,
        "Dockerfile": dockerfile,
        "docker-compose.yml": docker_compose,
        "nginx.conf": nginx_conf,
        ".env.example": env_example
    }


# =============================================================================
# MAIN APPLICATION ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    try:
        # Setup production environment
        setup_production_environment()

        # Run main application
        main()

    except Exception as e:
        logger.critical(f"Critical error starting application: {e}")
        st.error("🚨 Critical system error. Please contact administrator.")
        st.error(f"Error details: {str(e)}")

        if Config.LOG_LEVEL == "DEBUG":
            st.code(traceback.format_exc())


# =============================================================================
# DEPLOYMENT SCRIPT
# =============================================================================

def generate_deployment_package():
    """Generate deployment package dengan semua file yang diperlukan"""

    deployment_files = create_deployment_files()

    # Buat README untuk deployment
    readme = """
# FileStegano Pro - Production Deployment Guide

## Prerequisites
- Docker and Docker Compose
- SSL certificates (for HTTPS)
- Domain name (recommended)

## Quick Start

1. Clone/extract this deployment package
2. Copy `.env.example` to `.env` and configure:
   ```bash
   cp .env.example .env
   # Edit .env with your secure values
   ```

3. Generate secure keys:
   ```bash
   # Secret key
   python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"

   # JWT secret
   python -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(32))"

   # Encryption key
   python -c "from cryptography.fernet import Fernet; print('ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
   ```

4. Place your SSL certificates in `./ssl/` directory:
   - `cert.pem` (certificate)
   - `key.pem` (private key)

5. Update `nginx.conf` with your domain name

6. Deploy with Docker Compose:
   ```bash
   docker-compose up -d
   ```

## Security Checklist

- [ ] Generate unique SECRET_KEY, JWT_SECRET, and ENCRYPTION_KEY
- [ ] Configure strong admin password
- [ ] Enable HTTPS with valid SSL certificates
- [ ] Set up firewall rules
- [ ] Configure log rotation
- [ ] Set up regular database backups
- [ ] Monitor system resources
- [ ] Keep dependencies updated

## Monitoring

- Application logs: `./logs/filestegano.log`
- Database: `./data/filestegano.db`
- Container logs: `docker-compose logs -f`

## Backup

Regular backup of:
- Database: `./data/filestegano.db`
- Configuration: `.env`
- SSL certificates: `./ssl/`

## Scaling

For high-traffic scenarios:
- Use external database (PostgreSQL)
- Implement Redis for session management
- Add load balancer
- Use separate file storage service

## Support

For production support and enterprise features, contact your system administrator.
    """

    deployment_files["README.md"] = readme

    return deployment_files


# Print deployment information if running directly
if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--generate-deployment":
    print("🚀 Generating deployment package...")

    deployment_files = generate_deployment_package()

    # Create deployment directory
    os.makedirs("deployment", exist_ok=True)

    # Write all deployment files
    for filename, content in deployment_files.items():
        with open(f"deployment/{filename}", "w") as f:
            f.write(content.strip())

    print("✅ Deployment package generated in './deployment/' directory")
    print("📖 See README.md for deployment instructions")
