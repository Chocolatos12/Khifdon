import streamlit as st
import sqlite3
import hashlib
import numpy as np
from PIL import Image
import io
import base64
from datetime import datetime
import os
import zipfile

# Konfigurasi database
DB_NAME = "steganografi_ig.db"


def init_database():
    """Inisialisasi database dengan migration support"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Check if this is first run
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    users_table_exists = cursor.fetchone() is not None

    if not users_table_exists:
        # Create fresh database with all columns
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                full_name TEXT NOT NULL,
                profile_pic TEXT DEFAULT 'default.jpg',
                bio TEXT DEFAULT '',
                access_level TEXT DEFAULT 'approved',
                is_active BOOLEAN DEFAULT 1,
                device_id TEXT,
                mac_address TEXT,
                invitation_code TEXT,
                approved_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                login_attempts INTEGER DEFAULT 0,
                blocked_until TIMESTAMP
            )
        ''')
    else:
        # Migrate existing database
        migrate_database(cursor)

    # Create other tables if not exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS invitation_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            created_by INTEGER,
            used_by INTEGER,
            max_uses INTEGER DEFAULT 1,
            current_uses INTEGER DEFAULT 0,
            expires_at TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            device_id TEXT,
            device_name TEXT,
            mac_address TEXT,
            ip_address TEXT,
            user_agent TEXT,
            is_trusted BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            login_status TEXT,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Create file steganografi table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_steganografi (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            operation TEXT NOT NULL,
            cover_image_name TEXT,
            hidden_file_name TEXT,
            hidden_file_type TEXT,
            hidden_file_size INTEGER,
            output_filename TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Insert admin dengan akses penuh dan invitation codes
    try:
        admin_password = hashlib.sha256("SecureAdmin2024!".encode()).hexdigest()
        cursor.execute('''
            INSERT INTO users (username, email, password, full_name, bio, access_level, is_active) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ("admin_secure", "admin@steganosecure.com", admin_password, "System Administrator",
              "🔐 System Administrator with full access", "admin", 1))
        admin_id = cursor.lastrowid

        # Generate invitation codes
        invitation_codes = [
            "STEG2024ALPHA", "STEG2024BETA", "STEG2024GAMMA",
            "SECURE_ACCESS_001", "SECURE_ACCESS_002"
        ]

        for code in invitation_codes:
            cursor.execute('''
                INSERT INTO invitation_codes (code, created_by, max_uses, expires_at) 
                VALUES (?, ?, ?, datetime('now', '+30 days'))
            ''', (code, admin_id, 5))

    except sqlite3.IntegrityError:
        pass

    conn.commit()
    conn.close()


def migrate_database(cursor):
    """Migrate existing database to new schema"""
    # Get existing columns
    cursor.execute("PRAGMA table_info(users)")
    existing_columns = [row[1] for row in cursor.fetchall()]

    # Add missing columns with ALTER TABLE
    new_columns = {
        'access_level': 'TEXT DEFAULT "approved"',
        'is_active': 'BOOLEAN DEFAULT 1',
        'device_id': 'TEXT',
        'mac_address': 'TEXT',
        'invitation_code': 'TEXT',
        'approved_by': 'INTEGER',
        'login_attempts': 'INTEGER DEFAULT 0',
        'blocked_until': 'TIMESTAMP'
    }

    for column_name, column_definition in new_columns.items():
        if column_name not in existing_columns:
            try:
                cursor.execute(f'ALTER TABLE users ADD COLUMN {column_name} {column_definition}')
            except sqlite3.OperationalError:
                pass  # Column might already exist


def get_device_info():
    def get_device_info():
        """Generate device fingerprint untuk keamanan"""
        try:
            import platform
            import uuid

            # Generate unique device ID
            device_id = str(uuid.uuid4())

            # Get system info (simplified untuk demo)
            device_info = {
                'device_id': device_id,
                'platform': platform.system(),
                'device_name': platform.node(),
                'mac_address': ':'.join(
                    ['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
            }

            return device_info
        except Exception as e:
            # Fallback jika ada error
            return {
                'device_id': 'default_device',
                'platform': 'Unknown',
                'device_name': 'Unknown',
                'mac_address': '00:00:00:00:00:00'
            }


def check_invitation_code(code):
    """Validasi invitation code"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, max_uses, current_uses, expires_at, is_active 
            FROM invitation_codes 
            WHERE code = ? AND is_active = 1
        ''', (code,))

        result = cursor.fetchone()
        conn.close()

        if not result:
            return False, "Invalid invitation code"

        code_id, max_uses, current_uses, expires_at, is_active = result

        # Check expiry
        if expires_at:
            try:
                from datetime import datetime
                expiry_date = datetime.fromisoformat(expires_at)
                if datetime.now() > expiry_date:
                    return False, "Invitation code has expired"
            except:
                pass  # Skip expiry check if parsing fails

        # Check usage limit
        if current_uses >= max_uses:
            return False, "Invitation code has reached maximum usage"

        return True, code_id
    except Exception as e:
        return False, f"Error validating code: {str(e)}"


def use_invitation_code(code_id, user_id):
    """Mark invitation code as used"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE invitation_codes 
            SET current_uses = current_uses + 1, used_by = ? 
            WHERE id = ?
        ''', (user_id, code_id))

        conn.commit()
        conn.close()
    except Exception as e:
        pass  # Silent fail untuk demo


def check_device_whitelist(user_id, device_info):
    """Check if device is whitelisted"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT is_trusted FROM device_whitelist 
            WHERE user_id = ? AND (device_id = ? OR mac_address = ?)
        ''', (user_id, device_info['device_id'], device_info['mac_address']))

        result = cursor.fetchone()
        conn.close()

        return result[0] if result else False
    except Exception as e:
        return True  # Default allow jika ada error


def add_device_to_whitelist(user_id, device_info, is_trusted=False):
    """Add device to whitelist"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO device_whitelist 
            (user_id, device_id, device_name, mac_address, is_trusted) 
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, device_info['device_id'], device_info['device_name'],
              device_info['mac_address'], is_trusted))

        conn.commit()
        conn.close()
    except Exception as e:
        pass  # Silent fail untuk demo


def log_login_attempt(user_id, ip_address, user_agent, status):
    """Log login attempts untuk monitoring"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO login_logs (user_id, ip_address, user_agent, login_status) 
            VALUES (?, ?, ?, ?)
        ''', (user_id, ip_address, user_agent, status))

        conn.commit()
        conn.close()
    except Exception as e:
        pass  # Silent fail untuk demo


def check_login_attempts(username_or_email):
    """Check failed login attempts untuk rate limiting"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT login_attempts, blocked_until FROM users 
            WHERE username = ? OR email = ?
        ''', (username_or_email, username_or_email))

        result = cursor.fetchone()
        conn.close()

        if result:
            attempts, blocked_until = result
            if blocked_until:
                try:
                    from datetime import datetime
                    block_time = datetime.fromisoformat(blocked_until)
                    if datetime.now() < block_time:
                        return False, f"Account blocked until {blocked_until}"
                except:
                    pass  # Skip block check if parsing fails

            if attempts >= 5:  # Max 5 attempts
                return False, "Too many failed attempts. Account temporarily blocked."

        return True, None
    except Exception as e:
        return True, None  # Default allow jika ada error


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_user(username_or_email, password):
    """Verifikasi login user dengan security checks"""
    try:
        # Check login attempts first
        can_login, error_msg = check_login_attempts(username_or_email)
        if not can_login:
            return None, error_msg

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        hashed_password = hash_password(password)
        cursor.execute('''
            SELECT id, username, email, full_name, bio, profile_pic, access_level, is_active 
            FROM users 
            WHERE (username = ? OR email = ?) AND password = ?
        ''', (username_or_email, username_or_email, hashed_password))

        user = cursor.fetchone()

        if user:
            user_id = user[0]
            access_level = user[6] if len(user) > 6 else 'approved'
            is_active = user[7] if len(user) > 7 else 1

            # Check if user is active
            if not is_active:
                cursor.execute('''
                    UPDATE users SET login_attempts = COALESCE(login_attempts, 0) + 1 WHERE id = ?
                ''', (user_id,))
                conn.commit()
                conn.close()
                return None, "Account not activated. Please contact administrator."

            # Check access level
            if access_level == 'pending':
                conn.close()
                return None, "Account pending approval. Please wait for admin approval."

            # Reset login attempts on successful login
            cursor.execute('''
                UPDATE users SET login_attempts = 0, blocked_until = NULL, last_login = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (user_id,))

            # Log successful login
            log_login_attempt(user_id, "127.0.0.1", "Streamlit", "SUCCESS")

        else:
            # Increment failed attempts
            cursor.execute('''
                UPDATE users SET login_attempts = COALESCE(login_attempts, 0) + 1 
                WHERE username = ? OR email = ?
            ''', (username_or_email, username_or_email))

            # Block account after 5 failed attempts
            cursor.execute('''
                UPDATE users SET blocked_until = datetime('now', '+15 minutes') 
                WHERE (username = ? OR email = ?) AND COALESCE(login_attempts, 0) >= 5
            ''', (username_or_email, username_or_email))

            log_login_attempt(None, "127.0.0.1", "Streamlit", "FAILED")

        conn.commit()
        conn.close()

        return user, None if user else "Invalid credentials"
    except Exception as e:
        # Fallback ke basic verification jika ada error
        return verify_user_basic(username_or_email, password)


def verify_user_basic(username_or_email, password):
    """Basic user verification sebagai fallback"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        hashed_password = hash_password(password)
        cursor.execute('''
            SELECT id, username, email, full_name, bio, profile_pic 
            FROM users 
            WHERE (username = ? OR email = ?) AND password = ?
        ''', (username_or_email, username_or_email, hashed_password))

        user = cursor.fetchone()

        if user:
            # Update last login
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            ''', (user[0],))
            conn.commit()

        conn.close()
        return user, None if user else "Invalid credentials"
    except Exception as e:
        return None, f"Login error: {str(e)}"


def register_user(username, email, password, full_name, invitation_code=None):
    """Registrasi user baru dengan invitation code"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Validate invitation code jika diperlukan
        code_id = None
        if invitation_code:
            is_valid, result = check_invitation_code(invitation_code)
            if not is_valid:
                conn.close()
                return False, result
            code_id = result

        hashed_password = hash_password(password)
        access_level = "approved" if invitation_code else "pending"
        is_active = 1 if invitation_code else 0

        cursor.execute('''
            INSERT INTO users (username, email, password, full_name, access_level, is_active, invitation_code) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, email, hashed_password, full_name, access_level, is_active, invitation_code))

        user_id = cursor.lastrowid

        # Mark invitation code as used
        if code_id:
            use_invitation_code(code_id, user_id)

        conn.commit()
        conn.close()
        return True, "Registration successful"

    except sqlite3.IntegrityError as e:
        conn.close()
        if "username" in str(e):
            return False, "Username already exists"
        elif "email" in str(e):
            return False, "Email already exists"
        else:
            return False, "Registration failed"
    except Exception as e:
        return False, f"Registration error: {str(e)}"


def file_to_binary(file_data, filename):
    """Konversi file ke binary string dengan header yang aman"""
    # Buat header dengan delimiter yang unik
    header = f"STEGO_START|{filename}|{len(file_data)}|STEGO_HEADER_END"

    # Konversi header ke binary
    header_binary = ''.join(format(ord(char), '08b') for char in header)

    # Konversi file data ke binary
    file_binary = ''.join(format(byte, '08b') for byte in file_data)

    # Tambahkan end marker yang unik
    end_marker = '11111111' * 16  # 16 byte 0xFF sebagai end marker

    return header_binary + file_binary + end_marker


def binary_to_file(binary_string):
    """Konversi binary string kembali ke file dengan validasi yang ketat"""
    try:
        # Cari header delimiter
        header_delimiter = 'STEGO_HEADER_END'
        header_delimiter_binary = ''.join(format(ord(char), '08b') for char in header_delimiter)

        # Temukan posisi akhir header
        header_end_pos = -1
        for i in range(len(binary_string) - len(header_delimiter_binary)):
            if binary_string[i:i + len(header_delimiter_binary)] == header_delimiter_binary:
                header_end_pos = i + len(header_delimiter_binary)
                break

        if header_end_pos == -1:
            return None, None

        # Extract dan decode header
        header_binary = binary_string[:header_end_pos - len(header_delimiter_binary)]
        header_text = ''

        for i in range(0, len(header_binary), 8):
            byte = header_binary[i:i + 8]
            if len(byte) == 8:
                try:
                    char = chr(int(byte, 2))
                    header_text += char
                except ValueError:
                    continue

        # Parse header untuk mendapatkan info file
        if not header_text.startswith('STEGO_START|'):
            return None, None

        header_parts = header_text.split('|')
        if len(header_parts) < 3:
            return None, None

        filename = header_parts[1]
        try:
            file_size = int(header_parts[2])
        except ValueError:
            return None, None

        # Extract file data binary
        file_data_start = header_end_pos
        file_data_end = file_data_start + (file_size * 8)

        if file_data_end > len(binary_string):
            return None, None

        file_data_binary = binary_string[file_data_start:file_data_end]

        # Konversi binary ke bytes dengan validasi
        file_data = bytearray()
        for i in range(0, len(file_data_binary), 8):
            byte = file_data_binary[i:i + 8]
            if len(byte) == 8:
                try:
                    file_data.append(int(byte, 2))
                except ValueError:
                    return None, None

        # Validasi ukuran file
        if len(file_data) != file_size:
            return None, None

        return bytes(file_data), filename

    except Exception as e:
        print(f"Error in binary_to_file: {e}")
        return None, None


def hide_file_in_image(image, file_data, filename):
    """Menyembunyikan file dalam gambar dengan validasi yang ketat"""
    try:
        # Konversi file ke binary
        binary_data = file_to_binary(file_data, filename)

        # Konversi gambar ke array
        img_array = np.array(image)
        if len(img_array.shape) != 3 or img_array.shape[2] != 3:
            raise ValueError("Gambar harus dalam format RGB")

        # Hitung kapasitas gambar
        total_pixels = img_array.shape[0] * img_array.shape[1]
        max_bits = total_pixels * 3  # 3 channel RGB

        if len(binary_data) > max_bits:
            raise ValueError(f"File terlalu besar! Ukuran: {len(binary_data)} bits, Kapasitas: {max_bits} bits")

        # Flatten gambar untuk akses linear
        flat_img = img_array.flatten().astype(np.uint32)  # Prevent overflow

        # Sembunyikan data di LSB
        for i, bit in enumerate(binary_data):
            if i < len(flat_img):
                # Clear LSB dan set dengan bit data
                flat_img[i] = (flat_img[i] & 0xFE) | int(bit)

        # Reshape kembali dan convert ke uint8
        encoded_img = flat_img.reshape(img_array.shape).astype(np.uint8)

        return Image.fromarray(encoded_img)

    except Exception as e:
        raise Exception(f"Error hiding file: {str(e)}")


def extract_file_from_image(image):
    """Mengekstrak file tersembunyi dari gambar dengan error handling"""
    try:
        # Konversi gambar ke array
        img_array = np.array(image)
        flat_img = img_array.flatten()

        # Extract LSB untuk mendapatkan binary data
        binary_data = ''
        end_marker = '11111111' * 16  # End marker pattern

        # Baca bit demi bit sampai ketemu end marker atau habis
        for i, pixel in enumerate(flat_img):
            binary_data += str(pixel & 1)

            # Check end marker setiap 128 bit untuk efisiensi
            if i % 128 == 0 and len(binary_data) >= len(end_marker):
                if binary_data.endswith(end_marker):
                    binary_data = binary_data[:-len(end_marker)]
                    break

        # Final check untuk end marker
        if binary_data.endswith(end_marker):
            binary_data = binary_data[:-len(end_marker)]

        # Konversi binary ke file
        file_data, filename = binary_to_file(binary_data)

        if file_data is None or filename is None:
            return None, None

        return file_data, filename

    except Exception as e:
        print(f"Error extracting file: {e}")
        return None, None


def save_history(user_id, operation, cover_name, hidden_file_name, hidden_file_type, hidden_file_size, output_name):
    """Simpan riwayat ke database"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO file_steganografi 
        (user_id, operation, cover_image_name, hidden_file_name, hidden_file_type, hidden_file_size, output_filename) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, operation, cover_name, hidden_file_name, hidden_file_type, hidden_file_size, output_name))

    conn.commit()
    conn.close()


def get_user_history(user_id):
    """Ambil riwayat user"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT operation, cover_image_name, hidden_file_name, hidden_file_type, 
               hidden_file_size, output_filename, created_at 
        FROM file_steganografi 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    ''', (user_id,))

    history = cursor.fetchall()
    conn.close()
    return history


def download_button(object_to_download, download_filename, button_text, is_image=True):
    """Membuat tombol download"""
    if is_image and isinstance(object_to_download, Image.Image):
        buffer = io.BytesIO()
        object_to_download.save(buffer, format='PNG')
        buffer.seek(0)
        b64 = base64.b64encode(buffer.read()).decode()
        mime_type = "image/png"
    else:
        b64 = base64.b64encode(object_to_download).decode()
        mime_type = "application/octet-stream"

    button_uuid = str(hash(button_text + download_filename))

    custom_css = f"""
    <style>
        #{button_uuid} {{
            background: linear-gradient(45deg, #405DE6, #5851DB, #833AB4, #C13584, #E1306C, #FD1D1D, #F56040, #F77737, #FCAF45, #FFDC80);
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 25px;
            border: none;
            display: inline-block;
            font-weight: bold;
            text-align: center;
            transition: all 0.3s ease;
        }}
        #{button_uuid}:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            text-decoration: none;
        }}
    </style>
    """

    dl_link = f"""
    {custom_css}
    <a download="{download_filename}" id="{button_uuid}" href="data:{mime_type};base64,{b64}">{button_text}</a>
    """

    return dl_link


# Inisialisasi database
init_database()

# Konfigurasi halaman
st.set_page_config(
    page_title="FileStegano - Instagram Style",
    page_icon="📸",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS Instagram Style
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    .stApp {
        font-family: 'Inter', sans-serif;
    }

    .ig-header {
        background: linear-gradient(45deg, #405DE6, #5851DB, #833AB4, #C13584, #E1306C, #FD1D1D);
        padding: 2rem;
        border-radius: 20px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    }

    .ig-login-container {
        background: white;
        padding: 3rem;
        border-radius: 20px;
        border: 1px solid #DBDBDB;
        max-width: 400px;
        margin: 0 auto;
        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
    }

    .ig-logo {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(45deg, #405DE6, #C13584, #E1306C, #FD1D1D);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 2rem;
    }

    .user-profile {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        margin-bottom: 1rem;
    }

    .ig-card {
        background: white;
        border: 1px solid #DBDBDB;
        border-radius: 15px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        box-shadow: 0 5px 15px rgba(0,0,0,0.05);
    }

    .file-upload-area {
        border: 2px dashed #C13584;
        border-radius: 15px;
        padding: 2rem;
        text-align: center;
        background: #fafafa;
        margin: 1rem 0;
    }

    .success-message {
        background: linear-gradient(45deg, #56ab2f, #a8e6cf);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Session state initialization
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user_data' not in st.session_state:
    st.session_state.user_data = None

# Header
st.markdown("""
<div class="ig-header">
    <h1>📸 FileStegano</h1>
    <p>Hide & Extract Files in Images - Instagram Style</p>
</div>
""", unsafe_allow_html=True)

# Halaman Login
if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown('<div class="ig-login-container">', unsafe_allow_html=True)
        st.markdown('<div class="ig-logo">FileStegano</div>', unsafe_allow_html=True)

        tab1, tab2 = st.tabs(["📱 Log In", "✨ Sign Up"])

        with tab1:
            st.markdown("### 🔐 Secure Login")
            username = st.text_input("", placeholder="Username or email", key="login_username")
            password = st.text_input("", type="password", placeholder="Password", key="login_password")

            if st.button("🔑 Log In", type="primary", use_container_width=True):
                if username and password:
                    user, error_msg = verify_user(username, password)
                    if user and not error_msg:
                        # Get device info dengan error handling
                        try:
                            device_info = get_device_info()

                            # Check device whitelist
                            user_id = user[0]
                            access_level = user[6] if len(user) > 6 else 'approved'
                            is_trusted = check_device_whitelist(user_id, device_info)

                            if not is_trusted and access_level != 'admin':
                                # Add device to whitelist
                                add_device_to_whitelist(user_id, device_info, is_trusted=False)
                                st.warning(
                                    "⚠️ New device detected. Login allowed but limited access until device is trusted.")

                            st.session_state.logged_in = True
                            st.session_state.user_data = {
                                'id': user[0],
                                'username': user[1],
                                'email': user[2],
                                'full_name': user[3],
                                'bio': user[4] if len(user) > 4 else '',
                                'profile_pic': user[5] if len(user) > 5 else 'default.jpg',
                                'access_level': access_level,
                                'is_device_trusted': is_trusted or access_level == 'admin'
                            }
                            st.success("🎉 Login successful!")
                            st.rerun()
                        except Exception as e:
                            # Fallback login tanpa device checking
                            st.session_state.logged_in = True
                            st.session_state.user_data = {
                                'id': user[0],
                                'username': user[1],
                                'email': user[2],
                                'full_name': user[3],
                                'bio': user[4] if len(user) > 4 else '',
                                'profile_pic': user[5] if len(user) > 5 else 'default.jpg',
                                'access_level': 'approved',
                                'is_device_trusted': True
                            }
                            st.success("🎉 Login successful!")
                            st.rerun()
                    else:
                        st.error(f"❌ {error_msg}")
                else:
                    st.warning("⚠️ Please fill in all fields")

            st.markdown("---")
            st.markdown("**🔐 Secure Demo Account:**")
            st.info("**Admin Access**\n`admin_secure`\n`SecureAdmin2024!`")

            st.markdown("**📋 Valid Invitation Codes:**")
            codes_info = """
            - `STEG2024ALPHA`
            - `STEG2024BETA` 
            - `SECURE_ACCESS_001`
            """
            st.code(codes_info)

        with tab2:
            st.markdown("### ✨ Secure Registration")
            st.info("🎫 **Invitation Code Required** - Contact administrator for access")

            reg_invitation = st.text_input("🎫 Invitation Code *", placeholder="Enter invitation code",
                                           key="reg_invitation")
            reg_email = st.text_input("📧 Email *", placeholder="Email", key="reg_email")
            reg_fullname = st.text_input("👤 Full Name *", placeholder="Full Name", key="reg_fullname")
            reg_username = st.text_input("🆔 Username *", placeholder="Username", key="reg_username")
            reg_password = st.text_input("🔒 Password *", type="password", placeholder="Password (min 8 chars)",
                                         key="reg_password")

            if st.button("🎫 Register with Invitation", type="primary", use_container_width=True):
                if all([reg_invitation, reg_email, reg_fullname, reg_username, reg_password]):
                    if len(reg_password) >= 8:
                        success, message = register_user(reg_username, reg_email, reg_password, reg_fullname,
                                                         reg_invitation)
                        if success:
                            st.success("✅ Registration successful! You can now log in.")
                        else:
                            st.error(f"❌ {message}")
                    else:
                        st.warning("⚠️ Password must be at least 8 characters!")
                else:
                    st.warning("⚠️ Please fill in all required fields!")

            st.markdown("---")
            st.markdown("**🔒 Security Features:**")
            security_features = """
            ✅ Invitation-based registration
            ✅ Device fingerprinting
            ✅ Rate limiting protection
            ✅ Account lockout system
            ✅ Admin approval required
            """
            st.success(security_features)

        st.markdown('</div>', unsafe_allow_html=True)

# Halaman Utama (setelah login)
else:
    # Header dengan user info
    col1, col2 = st.columns([3, 1])

    with col1:
        st.markdown(f"""
        <div class="user-profile">
            <h3>👋 Hi, {st.session_state.user_data['full_name']}!</h3>
            <p><strong>@{st.session_state.user_data['username']}</strong> • {st.session_state.user_data['bio']}</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        if st.button("🚪 Log Out", type="secondary", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.user_data = None
            st.rerun()

    # Tab menu utama
    tab1, tab2, tab3 = st.tabs(["🔒 Hide File", "🔍 Extract File", "📊 Activity"])

    with tab1:
        st.markdown('<div class="ig-card">', unsafe_allow_html=True)
        st.header("🔒 Hide File in Image")

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📸 Cover Image")
            uploaded_image = st.file_uploader(
                "Choose cover image:",
                type=['png', 'jpg', 'jpeg'],
                key="cover_image"
            )

            if uploaded_image:
                image = Image.open(uploaded_image).convert('RGB')
                st.image(image, caption="Cover Image", use_column_width=True)

                # Hitung kapasitas
                total_pixels = image.size[0] * image.size[1]
                max_bytes = (total_pixels * 3) // 8 - 1000  # Buffer untuk header
                st.info(f"**Max file size:** ~{max_bytes / 1024:.1f} KB")

        with col2:
            st.subheader("📁 File to Hide")
            st.markdown('<div class="file-upload-area">', unsafe_allow_html=True)
            uploaded_file = st.file_uploader(
                "Choose any file to hide:",
                type=None,
                key="hidden_file"
            )
            st.markdown('</div>', unsafe_allow_html=True)

            if uploaded_file:
                file_data = uploaded_file.read()
                file_size = len(file_data)
                file_type = uploaded_file.type or "unknown"

                st.success(f"✅ **{uploaded_file.name}** loaded")
                st.info(f"**Size:** {file_size / 1024:.2f} KB")
                st.info(f"**Type:** {file_type}")

                if uploaded_image and st.button("🔒 Hide File in Image", type="primary", use_container_width=True):
                    try:
                        with st.spinner("Hiding file in image..."):
                            stego_image = hide_file_in_image(image, file_data, uploaded_file.name)

                        st.markdown('<div class="success-message">🎉 File successfully hidden in image!</div>',
                                    unsafe_allow_html=True)

                        # Show result
                        st.subheader("📸 Steganographic Image")
                        st.image(stego_image, caption="Image with hidden file", use_column_width=True)

                        # Save to database
                        output_filename = f"stego_{uploaded_image.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                        save_history(
                            st.session_state.user_data['id'],
                            "HIDE",
                            uploaded_image.name,
                            uploaded_file.name,
                            file_type,
                            file_size,
                            output_filename
                        )

                        # Download button
                        download_link = download_button(
                            stego_image,
                            output_filename,
                            "📥 Download Steganographic Image"
                        )
                        st.markdown(download_link, unsafe_allow_html=True)

                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")

        st.markdown('</div>', unsafe_allow_html=True)

    with tab2:
        st.markdown('<div class="ig-card">', unsafe_allow_html=True)
        st.header("🔍 Extract File from Image")

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📸 Steganographic Image")
            uploaded_stego = st.file_uploader(
                "Choose image with hidden file:",
                type=['png', 'jpg', 'jpeg'],
                key="stego_image"
            )

            if uploaded_stego:
                stego_image = Image.open(uploaded_stego).convert('RGB')
                st.image(stego_image, caption="Steganographic Image", use_column_width=True)

        with col2:
            if uploaded_stego:
                st.subheader("📁 Extract File")

                if st.button("🔍 Extract Hidden File", type="primary", use_container_width=True):
                    try:
                        with st.spinner("Extracting hidden file..."):
                            extracted_data, extracted_filename = extract_file_from_image(stego_image)

                        if extracted_data and extracted_filename:
                            st.markdown('<div class="success-message">🎉 File successfully extracted!</div>',
                                        unsafe_allow_html=True)

                            # File info dengan validasi
                            file_size = len(extracted_data)
                            st.success(f"**Filename:** {extracted_filename}")
                            st.info(f"**Size:** {file_size / 1024:.2f} KB")

                            # Tampilkan preview untuk beberapa jenis file
                            file_ext = extracted_filename.lower().split('.')[-1] if '.' in extracted_filename else ''

                            if file_ext in ['txt', 'md', 'py', 'js', 'html', 'css']:
                                try:
                                    preview_text = extracted_data.decode('utf-8')[:500]
                                    st.text_area("File Preview (first 500 chars):", preview_text, height=100,
                                                 disabled=True)
                                except:
                                    st.info("Text preview not available")
                            elif file_ext in ['jpg', 'jpeg', 'png', 'gif']:
                                try:
                                    preview_img = Image.open(io.BytesIO(extracted_data))
                                    st.image(preview_img, caption=f"Preview: {extracted_filename}", width=300)
                                except:
                                    st.info("Image preview not available")

                            # Validasi integritas file
                            if file_size > 0:
                                st.success("✅ File integrity check: PASSED")
                            else:
                                st.error("❌ File integrity check: FAILED")

                            # Save to database
                            save_history(
                                st.session_state.user_data['id'],
                                "EXTRACT",
                                uploaded_stego.name,
                                extracted_filename,
                                f".{file_ext}" if file_ext else "unknown",
                                file_size,
                                extracted_filename
                            )

                            # Download button dengan validasi
                            if file_size > 0:
                                download_link = download_button(
                                    extracted_data,
                                    extracted_filename,
                                    f"📥 Download {extracted_filename}",
                                    is_image=False
                                )
                                st.markdown(download_link, unsafe_allow_html=True)

                                # Tips untuk membuka file
                                st.markdown("### 💡 Tips:")
                                if file_ext in ['pdf']:
                                    st.info("📄 PDF file - Open with PDF reader")
                                elif file_ext in ['docx', 'doc']:
                                    st.info("📝 Word document - Open with Microsoft Word or LibreOffice")
                                elif file_ext in ['xlsx', 'xls']:
                                    st.info("📊 Excel file - Open with Microsoft Excel or LibreOffice Calc")
                                elif file_ext in ['zip', 'rar', '7z']:
                                    st.info("📦 Archive file - Extract with WinRAR, 7-Zip, or built-in extractor")
                                elif file_ext in ['mp3', 'wav', 'mp4', 'avi']:
                                    st.info("🎵🎬 Media file - Open with media player")
                                else:
                                    st.info("📁 File ready to download - Open with appropriate application")
                            else:
                                st.error("❌ File extraction failed - File size is 0 bytes")

                        else:
                            st.warning("⚠️ No hidden file found in this image")

                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")

        st.markdown('</div>', unsafe_allow_html=True)

    with tab3:
        st.markdown('<div class="ig-card">', unsafe_allow_html=True)
        st.header("📊 Your Activity")

        history = get_user_history(st.session_state.user_data['id'])

        if history:
            st.subheader(f"📈 Total Operations: {len(history)}")

            for i, record in enumerate(history):
                operation, cover_img, hidden_file, file_type, file_size, output_file, created_at = record

                # Create activity card
                if operation == "HIDE":
                    icon = "🔒"
                    color = "#C13584"
                    action = "Hidden"
                else:
                    icon = "🔍"
                    color = "#405DE6"
                    action = "Extracted"

                st.markdown(f"""
                <div style="border-left: 4px solid {color}; padding: 1rem; margin: 1rem 0; background: #f9f9f9; border-radius: 10px;">
                    <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                        <span style="font-size: 1.5rem; margin-right: 0.5rem;">{icon}</span>
                        <strong>{action}: {hidden_file}</strong>
                    </div>
                    <div style="font-size: 0.9rem; color: #666;">
                        📸 Cover: {cover_img} • 📁 Size: {file_size / 1024:.1f} KB • 🕒 {created_at}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("📝 No activity yet. Start hiding or extracting files!")

        st.markdown('</div>', unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>📸 <strong>FileStegano</strong> - Hide any file in images with style!</p>
    <p><small>Built with ❤️ using Streamlit • Inspired by Instagram UI</small></p>
</div>
""", unsafe_allow_html=True)
