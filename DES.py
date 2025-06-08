import streamlit as st
from Crypto.Cipher import DES
import base64
import pandas as pd
import sqlite3
from datetime import date

# ===== Utility Functions =====
def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt_field(text, key):
    des = DES.new(key.encode(), DES.MODE_ECB)
    padded = pad(text)
    encrypted = des.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_field(cipher_text, key):
    des = DES.new(key.encode(), DES.MODE_ECB)
    decrypted = des.decrypt(base64.b64decode(cipher_text))
    return decrypted.decode().rstrip()

# ===== Database Setup =====
def init_db():
    conn = sqlite3.connect("biodata_des.db")
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS biodata_plain (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nama TEXT,
        nim TEXT,
        tanggal_lahir TEXT,
        alamat TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS biodata_encrypted (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nama TEXT,
        nim TEXT,
        tanggal_lahir TEXT,
        alamat TEXT
    )
    """)
    conn.commit()
    conn.close()

def save_plain_data(data):
    conn = sqlite3.connect("biodata_des.db")
    c = conn.cursor()
    c.execute("""
    INSERT INTO biodata_plain (nama, nim, tanggal_lahir, alamat)
    VALUES (?, ?, ?, ?)
    """, (data["Nama"], data["NIM"], data["Tanggal Lahir"], data["Alamat"]))
    conn.commit()
    conn.close()

def save_encrypted_data(data):
    conn = sqlite3.connect("biodata_des.db")
    c = conn.cursor()
    c.execute("""
    INSERT INTO biodata_encrypted (nama, nim, tanggal_lahir, alamat)
    VALUES (?, ?, ?, ?)
    """, (data["Nama"], data["NIM"], data["Tanggal Lahir"], data["Alamat"]))
    conn.commit()
    conn.close()

# ===== Session State Init =====
if "plain_data" not in st.session_state:
    st.session_state.plain_data = {}
if "encrypted_data" not in st.session_state:
    st.session_state.encrypted_data = {}
if "key" not in st.session_state:
    st.session_state.key = ""

# ===== Initialize DB =====
init_db()

# ===== App Config =====
st.set_page_config("Enkripsi Biodata DES", "🔐")
st.title("🔐 Aplikasi Enkripsi & Dekripsi Biodata (DES)")
menu = st.sidebar.radio("📋 Menu", ["Input Data Diri", "Enkripsi", "Dekripsi"])

# ===== 1. Input Data Diri =====
if menu == "Input Data Diri":
    st.subheader("📥 Input Data Diri")
    nama = st.text_input("Nama Lengkap")
    nim = st.text_input("NIM")
    # Batasi tanggal lahir antara 1 Jan 2000 dan 31 Des 2025
    ttl = st.date_input("Tanggal Lahir", min_value=date(2000, 1, 1), max_value=date(2025, 12, 31))
    alamat = st.text_area("Alamat")
    key = st.text_input("Kunci Enkripsi (8 karakter)", max_chars=8, type="password")

    if st.button("Simpan Data"):
        if len(key) != 8:
            st.warning("⚠️ Kunci harus 8 karakter.")
        elif not all([nama.strip(), nim.strip(), alamat.strip()]):
            st.warning("⚠️ Semua data harus diisi.")
        else:
            st.session_state.plain_data = {
                "Nama": nama.strip(),
                "NIM": nim.strip(),
                "Tanggal Lahir": ttl.strftime("%d-%m-%Y"),
                "Alamat": alamat.strip()
            }
            st.session_state.key = key

            # Simpan data asli ke database
            save_plain_data(st.session_state.plain_data)
            st.success("✅ Data berhasil disimpan ke aplikasi dan database.")

# ===== 2. Enkripsi =====
elif menu == "Enkripsi":
    st.subheader("🔐 Enkripsi Data")

    if not st.session_state.plain_data:
        st.warning("⚠️ Silakan input data diri terlebih dahulu.")
    else:
        key = st.session_state.key
        encrypted = {
            k: encrypt_field(v, key)
            for k, v in st.session_state.plain_data.items()
        }
        st.session_state.encrypted_data = encrypted

        # Simpan data terenkripsi ke database
        save_encrypted_data(encrypted)

        df_enc = pd.DataFrame(encrypted.items(), columns=["Field", "Ciphertext"])
        st.dataframe(df_enc)

        csv = df_enc.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Download Enkripsi (CSV)", csv, "hasil_enkripsi.csv", "text/csv")

# ===== 3. Dekripsi =====
elif menu == "Dekripsi":
    st.subheader("🔓 Dekripsi Data")

    if not st.session_state.encrypted_data:
        st.warning("⚠️ Belum ada data terenkripsi.")
    else:
        input_key = st.text_input("Masukkan Kunci Dekripsi (8 karakter)", max_chars=8, type="password")
        if st.button("Dekripsi"):
            if input_key != st.session_state.key:
                st.error("❌ Kunci salah!")
            else:
                decrypted = {
                    k: decrypt_field(v, input_key)
                    for k, v in st.session_state.encrypted_data.items()
                }
                df_dec = pd.DataFrame(decrypted.items(), columns=["Field", "Plaintext"])
                st.dataframe(df_dec)
