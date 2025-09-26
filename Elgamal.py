import streamlit as st
import random

# -------------------------------
# FUNGSI UTAMA ELGAMAL
# -------------------------------

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def elgamal_keygen():
    p = 30803  # bilangan prima contoh
    g = 2
    x = random.randint(1, p - 2)   # private key
    y = pow(g, x, p)               # public key
    return p, g, y, x

def elgamal_encrypt(msg, p, g, y):
    msg_nums = [ord(ch) for ch in msg]
    cipher = []
    for m in msg_nums:
        k = random.randint(1, p - 2)
        a = pow(g, k, p)
        b = (pow(y, k, p) * m) % p
        cipher.append((a, b))
    return cipher

def elgamal_decrypt(cipher, p, x):
    plain_nums = []
    for a, b in cipher:
        s = pow(a, x, p)
        s_inv = modinv(s, p)
        m = (b * s_inv) % p
        plain_nums.append(m)
    return ''.join([chr(num) for num in plain_nums])

# -------------------------------
# STREAMLIT APP
# -------------------------------

st.title("🔐 ElGamal Cryptosystem Demo")

# Pastikan key sudah ada
if "keys" not in st.session_state:
    st.session_state["keys"] = elgamal_keygen()

# Ambil nilai kunci
p, g, y, x = st.session_state["keys"]

st.sidebar.subheader("🔑 Key Information")
st.sidebar.write(f"Public Key (p, g, y): ({p}, {g}, {y})")
st.sidebar.write(f"Private Key (x): {x}")

menu = st.radio("Pilih Mode:", ["Enkripsi", "Dekripsi"])

if menu == "Enkripsi":
    message = st.text_input("Masukkan pesan untuk dienkripsi:")
    if st.button("Enkripsi"):
        cipher = elgamal_encrypt(message, p, g, y)
        st.session_state["cipher"] = cipher
        st.success("Pesan berhasil dienkripsi!")
        st.write("Ciphertext:")
        st.code(cipher)

elif menu == "Dekripsi":
    if "cipher" in st.session_state:
        st.write("Ciphertext yang tersimpan:")
        st.code(st.session_state["cipher"])
        if st.button("Dekripsi"):
            plain = elgamal_decrypt(st.session_state["cipher"], p, x)
            st.success("Pesan berhasil didekripsi!")
            st.write("Plaintext:", plain)
    else:
        st.warning("Belum ada ciphertext, silakan enkripsi dulu.")
