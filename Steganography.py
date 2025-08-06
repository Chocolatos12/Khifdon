import streamlit as st
import sqlite3
import hashlib
import datetime
from PIL import Image
import numpy as np
import io
import base64
import secrets
import os
import zipfile

# Konfigurasi halaman
st.set_page_config(
    page_title="Steganografi App",
    page_icon="🔐",
    layout="wide"
)


# Inisialisasi database
def init_database():
    conn = sqlite3.connect('steganografi.db')
    cursor = conn.cursor()

    # Tabel users
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        invitation_code TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_admin BOOLEAN DEFAULT FALSE
    )
    ''')

    # Tabel invitation codes
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS invitation_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        created_by INTEGER,
        used_by INTEGER DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        used_at TIMESTAMP DEFAULT NULL,
        FOREIGN KEY (created_by) REFERENCES users (id),
        FOREIGN KEY (used_by) REFERENCES users (id)
    )
    ''')

    # Tabel activity logs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        activity_type TEXT NOT NULL,
        description TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    # Membuat admin pertama jika belum ada
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        admin_password = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute('''
        INSERT INTO users (username, password_hash, is_admin) 
        VALUES (?, ?, ?)
        ''', ("admin", admin_password, True))

        # Generate kode undangan pertama
        first_code = secrets.token_urlsafe(8)
        cursor.execute('''
        INSERT INTO invitation_codes (code, created_by) 
        VALUES (?, ?)
        ''', (first_code, 1))

    conn.commit()
    conn.close()


# Fungsi hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Fungsi login
def login_user(username, password):
    conn = sqlite3.connect('steganografi.db')
    cursor = conn.cursor()

    password_hash = hash_password(password)
    cursor.execute('''
    SELECT id, username, is_admin FROM users 
    WHERE username = ? AND password_hash = ?
    ''', (username, password_hash))

    user = cursor.fetchone()
    conn.close()

    if user:
        log_activity(user[0], "LOGIN", f"User {username} logged in")
        return {"id": user[0], "username": user[1], "is_admin": user[2]}
    return None


# Fungsi registrasi
def register_user(username, password, invitation_code):
    conn = sqlite3.connect('steganografi.db')
    cursor = conn.cursor()

    # Cek apakah kode undangan valid
    cursor.execute('''
    SELECT id, created_by FROM invitation_codes 
    WHERE code = ? AND used_by IS NULL
    ''', (invitation_code,))

    code_info = cursor.fetchone()
    if not code_info:
        conn.close()
        return False, "Kode undangan tidak valid atau sudah digunakan"

    # Cek apakah username sudah ada
    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Username sudah digunakan"

    # Daftar user baru
    password_hash = hash_password(password)
    cursor.execute('''
    INSERT INTO users (username, password_hash, invitation_code) 
    VALUES (?, ?, ?)
    ''', (username, password_hash, invitation_code))

    new_user_id = cursor.lastrowid

    # Update kode undangan sebagai terpakai
    cursor.execute('''
    UPDATE invitation_codes 
    SET used_by = ?, used_at = CURRENT_TIMESTAMP 
    WHERE id = ?
    ''', (new_user_id, code_info[0]))

    conn.commit()
    conn.close()

    log_activity(new_user_id, "REGISTER", f"New user {username} registered")
    return True, "Registrasi berhasil"


# Fungsi generate kode undangan
def generate_invitation_code(user_id):
    conn = sqlite3.connect('steganografi.db')
    cursor = conn.cursor()

    code = secrets.token_urlsafe(8)
    cursor.execute('''
    INSERT INTO invitation_codes (code, created_by) 
    VALUES (?, ?)
    ''', (code, user_id))

    conn.commit()
    conn.close()

    log_activity(user_id, "GENERATE_CODE", f"Generated invitation code: {code}")
    return code


# Fungsi log aktivitas
def log_activity(user_id, activity_type, description):
    conn = sqlite3.connect('steganografi.db')
    cursor = conn.cursor()

    cursor.execute('''
    INSERT INTO activity_logs (user_id, activity_type, description) 
    VALUES (?, ?, ?)
    ''', (user_id, activity_type, description))

    conn.commit()
    conn.close()


# Fungsi get aktivitas
def get_activities(user_id=None):
    conn = sqlite3.connect('steganografi.db')
    cursor = conn.cursor()

    if user_id:
        cursor.execute('''
        SELECT u.username, a.activity_type, a.description, a.timestamp 
        FROM activity_logs a 
        JOIN users u ON a.user_id = u.id 
        WHERE a.user_id = ?
        ORDER BY a.timestamp DESC LIMIT 50
        ''', (user_id,))
    else:
        cursor.execute('''
        SELECT u.username, a.activity_type, a.description, a.timestamp 
        FROM activity_logs a 
        JOIN users u ON a.user_id = u.id 
        ORDER BY a.timestamp DESC LIMIT 100
        ''')

    activities = cursor.fetchall()
    conn.close()
    return activities


# Fungsi untuk mengkonversi data ke binary
def data_to_binary(data):
    """Mengkonversi data bytes ke string binary"""
    return ''.join(format(byte, '08b') for byte in data)


# Fungsi untuk mengkonversi binary ke data
def binary_to_data(binary_str):
    """Mengkonversi string binary ke bytes"""
    data = bytearray()
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i + 8]
        if len(byte) == 8:
            data.append(int(byte, 2))
    return bytes(data)


# Fungsi steganografi - Hide File
def hide_file_in_image(image, file_data, filename):
    """Menyembunyikan file dalam gambar menggunakan LSB steganografi"""
    # Konversi ke RGB jika perlu dan buat copy
    if image.mode != 'RGB':
        image = image.convert('RGB')

    img_array = np.array(image, dtype=np.uint8)

    # Buat header dengan format yang lebih sederhana
    filename_bytes = filename.encode('utf-8')
    filename_len = len(filename_bytes)
    file_size = len(file_data)

    # Header: MAGIC(4) + filename_length(4) + filename + file_size(4) + file_data
    magic_header = b'STEG'  # Magic number untuk identifikasi
    header = magic_header
    header += filename_len.to_bytes(4, byteorder='big')
    header += filename_bytes
    header += file_size.to_bytes(4, byteorder='big')

    # Gabungkan header + data file
    full_data = header + file_data

    # Konversi ke binary
    data_bits = ''.join(format(byte, '08b') for byte in full_data)

    # Tambahkan delimiter di akhir
    delimiter = '11111111111111111111111111111111'  # 32-bit delimiter
    data_bits += delimiter

    # Flatten array gambar
    flat_img = img_array.flatten()

    # Cek kapasitas
    if len(data_bits) > len(flat_img):
        max_size = (len(flat_img) - 32) // 8  # -32 untuk delimiter
        return None, f"File terlalu besar! Maksimal: {max_size:,} bytes, File: {len(full_data):,} bytes"

    # Sembunyikan data bit per bit
    for i in range(len(data_bits)):
        flat_img[i] = (flat_img[i] & 0xFE) | int(data_bits[i])

    # Reshape kembali
    hidden_img = flat_img.reshape(img_array.shape)
    return Image.fromarray(hidden_img), "Success"


# Fungsi steganografi - Extract File
def extract_file_from_image(image):
    """Mengekstrak file dari gambar"""
    # Konversi ke RGB jika perlu
    if image.mode != 'RGB':
        image = image.convert('RGB')

    img_array = np.array(image, dtype=np.uint8)
    flat_img = img_array.flatten()

    # Extract bits
    binary_data = ''
    for pixel in flat_img:
        binary_data += str(pixel & 1)

    # Cari delimiter
    delimiter = '11111111111111111111111111111111'  # 32-bit delimiter
    end_index = binary_data.find(delimiter)

    if end_index == -1:
        return None, None, "Tidak ada data tersembunyi atau delimiter tidak ditemukan"

    # Ambil data sebelum delimiter
    data_bits = binary_data[:end_index]

    # Pastikan panjang data kelipatan 8
    if len(data_bits) % 8 != 0:
        return None, None, "Data bits tidak valid (bukan kelipatan 8)"

    try:
        # Konversi bits ke bytes
        data_bytes = bytearray()
        for i in range(0, len(data_bits), 8):
            byte_bits = data_bits[i:i + 8]
            data_bytes.append(int(byte_bits, 2))

        data_bytes = bytes(data_bytes)

        # Cek magic header
        if len(data_bytes) < 4 or data_bytes[:4] != b'STEG':
            return None, None, "Magic header tidak ditemukan - bukan file tersembunyi"

        # Parse header
        if len(data_bytes) < 8:
            return None, None, "Header terlalu pendek"

        # Ambil panjang nama file
        filename_length = int.from_bytes(data_bytes[4:8], byteorder='big')

        if filename_length > 255 or filename_length < 1:
            return None, None, f"Panjang nama file tidak valid: {filename_length}"

        # Cek apakah cukup data untuk nama file
        header_end = 8 + filename_length + 4
        if len(data_bytes) < header_end:
            return None, None, f"Data tidak cukup untuk header lengkap. Butuh: {header_end}, Ada: {len(data_bytes)}"

        # Ambil nama file
        try:
            filename = data_bytes[8:8 + filename_length].decode('utf-8')
        except UnicodeDecodeError:
            return None, None, "Nama file tidak dapat di-decode"

        # Ambil ukuran file
        file_size = int.from_bytes(data_bytes[8 + filename_length:header_end], byteorder='big')

        if file_size < 0 or file_size > 100 * 1024 * 1024:  # Max 100MB
            return None, None, f"Ukuran file tidak valid: {file_size}"

        # Cek apakah cukup data untuk file
        total_needed = header_end + file_size
        if len(data_bytes) < total_needed:
            return None, None, f"Data file tidak lengkap. Butuh: {total_needed}, Ada: {len(data_bytes)}, Header: {header_end}, File size: {file_size}"

        # Ambil data file
        file_data = data_bytes[header_end:header_end + file_size]

        return file_data, filename, "Success"

    except Exception as e:
        return None, None, f"Error saat parsing: {str(e)}"


# Fungsi untuk download gambar
def get_download_link(img, filename):
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    href = f'<a href="data:file/png;base64,{img_str}" download="{filename}">📥 Download Gambar</a>'
    return href


# Fungsi untuk download file
def get_file_download_link(file_data, filename):
    b64 = base64.b64encode(file_data).decode()
    href = f'<a href="data:application/octet-stream;base64,{b64}" download="{filename}">📁 Download {filename}</a>'
    return href


def main():
    init_database()

    # Session state
    if 'user' not in st.session_state:
        st.session_state.user = None

    # Sidebar untuk login/logout
    with st.sidebar:
        st.title("🔐 Steganografi App")

        if st.session_state.user is None:
            # Form Login/Register
            tab1, tab2 = st.tabs(["Login", "Register"])

            with tab1:
                st.subheader("Login")
                username = st.text_input("Username", key="login_username")
                password = st.text_input("Password", type="password", key="login_password")

                if st.button("Login"):
                    if username and password:
                        user = login_user(username, password)
                        if user:
                            st.session_state.user = user
                            st.success("Login berhasil!")
                            st.rerun()
                        else:
                            st.error("Username atau password salah")
                    else:
                        st.error("Harap isi semua field")

            with tab2:
                st.subheader("Register")
                reg_username = st.text_input("Username", key="reg_username")
                reg_password = st.text_input("Password", type="password", key="reg_password")
                invitation_code = st.text_input("Kode Undangan")

                if st.button("Register"):
                    if reg_username and reg_password and invitation_code:
                        success, message = register_user(reg_username, reg_password, invitation_code)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
                    else:
                        st.error("Harap isi semua field")

        else:
            # User sudah login
            st.write(f"👤 **{st.session_state.user['username']}**")

            # Generate invitation code
            if st.button("Generate Kode Undangan"):
                code = generate_invitation_code(st.session_state.user['id'])
                st.success(f"Kode Undangan: **{code}**")

            # Logout
            if st.button("Logout"):
                log_activity(st.session_state.user['id'], "LOGOUT",
                             f"User {st.session_state.user['username']} logged out")
                st.session_state.user = None
                st.rerun()

    # Main content
    if st.session_state.user is None:
        st.title("Selamat Datang di Aplikasi Steganografi")
        st.write("Silakan login atau register untuk menggunakan aplikasi.")
        st.info("**Info Admin Default:**\n- Username: admin\n- Password: admin123")

        # Informasi fitur
        st.markdown("""
        ### 🚀 Fitur Aplikasi:
        - 📁 **Hide File**: Sembunyikan file apapun dalam gambar
        - 🔍 **Extract File**: Ekstrak file tersembunyi dari gambar  
        - 📊 **Activity Log**: Pantau semua aktivitas
        - 🎫 **Invitation System**: Sistem undangan eksklusif
        """)

    else:
        st.title(f"Welcome, {st.session_state.user['username']}! 🎉")

        # Tabs untuk fitur utama
        tab1, tab2, tab3 = st.tabs([
            "📁 Hide File",
            "🔍 Extract File",
            "📊 Activity Log"
        ])

        with tab1:
            st.header("📁 Sembunyikan File dalam Gambar")

            col1, col2 = st.columns(2)

            with col1:
                st.subheader("Upload Gambar Cover")
                cover_image = st.file_uploader(
                    "Pilih gambar untuk menyembunyikan file",
                    type=['png', 'jpg', 'jpeg'],
                    key="cover_image"
                )

            with col2:
                st.subheader("Upload File yang Akan Disembunyikan")
                secret_file = st.file_uploader(
                    "Pilih file yang akan disembunyikan",
                    type=None,  # Semua jenis file
                    key="secret_file"
                )

            if cover_image is not None:
                image = Image.open(cover_image)
                st.image(image, caption="Gambar Cover", width=300)

                # Tampilkan info kapasitas
                img_array = np.array(image)
                max_bits = img_array.size
                max_bytes = max_bits // 8
                st.info(f"💾 Kapasitas maksimal: ~{max_bytes:,} bytes ({max_bytes / 1024:.1f} KB)")

            if secret_file is not None:
                file_data = secret_file.read()
                file_size = len(file_data)
                st.success(f"📄 File loaded: {secret_file.name} ({file_size:,} bytes)")

            if cover_image is not None and secret_file is not None:
                if st.button("🔒 Sembunyikan File", type="primary"):
                    with st.spinner("Menyembunyikan file..."):
                        hidden_image, status = hide_file_in_image(image, file_data, secret_file.name)

                        if hidden_image is not None:
                            st.success("✅ File berhasil disembunyikan!")
                            st.image(hidden_image, caption="Gambar dengan File Tersembunyi", width=300)

                            # Download link
                            st.markdown(
                                get_download_link(hidden_image, f"hidden_{cover_image.name}"),
                                unsafe_allow_html=True
                            )

                            log_activity(
                                st.session_state.user['id'],
                                "HIDE_FILE",
                                f"Hidden file {secret_file.name} in image {cover_image.name}"
                            )
                        else:
                            st.error(f"❌ {status}")

        with tab2:
            st.header("🔍 Ekstrak File dari Gambar")

            extract_file = st.file_uploader(
                "Upload gambar yang berisi file tersembunyi",
                type=['png', 'jpg', 'jpeg'],
                key="extract"
            )

            if extract_file is not None:
                image = Image.open(extract_file)
                st.image(image, caption="Gambar Input", width=300)

                if st.button("📁 Ekstrak File", type="primary"):
                    with st.spinner("Mengekstrak file..."):
                        file_data, filename, status = extract_file_from_image(image)

                        if file_data is not None:
                            st.success(f"✅ File ditemukan: {filename}")
                            st.info(f"📊 Ukuran file: {len(file_data):,} bytes")

                            # Download link
                            st.markdown(
                                get_file_download_link(file_data, filename),
                                unsafe_allow_html=True
                            )

                            log_activity(
                                st.session_state.user['id'],
                                "EXTRACT_FILE",
                                f"Extracted file {filename} from image: {extract_file.name}"
                            )
                        else:
                            st.error(f"❌ {status}")
                            # Debug info
                            with st.expander("🔍 Debug Info"):
                                img_array = np.array(image)
                                st.write(f"Image mode: {image.mode}")
                                st.write(f"Image size: {image.size}")
                                st.write(f"Array shape: {img_array.shape}")
                                st.write(f"Array dtype: {img_array.dtype}")

        with tab3:
            st.header("📊 Log Aktivitas")

            if st.session_state.user['is_admin']:
                # Admin bisa lihat semua aktivitas
                show_all = st.checkbox("Tampilkan semua aktivitas pengguna")
                activities = get_activities() if show_all else get_activities(st.session_state.user['id'])
            else:
                # User biasa hanya bisa lihat aktivitas sendiri
                activities = get_activities(st.session_state.user['id'])

            if activities:
                st.write("### Aktivitas Terbaru")
                for activity in activities:
                    username, activity_type, description, timestamp = activity

                    # Icon berdasarkan jenis aktivitas
                    icons = {
                        'LOGIN': '🔓',
                        'LOGOUT': '🔒',
                        'REGISTER': '📝',
                        'GENERATE_CODE': '🎫',
                        'HIDE_FILE': '📁',
                        'EXTRACT_FILE': '📤'
                    }
                    icon = icons.get(activity_type, '📋')

                    with st.expander(f"{icon} {activity_type} - {username} - {timestamp}"):
                        st.write(f"**Deskripsi:** {description}")
                        st.write(f"**Waktu:** {timestamp}")
            else:
                st.info("Belum ada aktivitas")


if __name__ == "__main__":
    main()
