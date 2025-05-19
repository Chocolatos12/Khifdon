import streamlit as st

def affine_encrypt(plaintext, a, b):
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            c = chr(((a * (ord(char) - base) + b) % 26) + base)
            ciphertext += c
        else:
            ciphertext += char
    return ciphertext

# Streamlit UI
st.title("🔐 Affine Cipher Encryption")

# Input section
plaintext = st.text_input("Masukkan Plaintext", "")
a = st.number_input("Masukkan kunci a (coprime dengan 26)", min_value=1, step=1)
b = st.number_input("Masukkan kunci b", min_value=0, step=1)

# Validasi nilai 'a' agar coprime dengan 26
from math import gcd
def is_coprime(a, m=26):
    return gcd(a, m) == 1

if st.button("Enkripsi"):
    if not is_coprime(int(a)):
        st.error("Kunci 'a' harus coprime dengan 26 untuk enkripsi yang valid.")
    else:
        ciphertext = affine_encrypt(plaintext, int(a), int(b))
        st.success(f"Ciphertext: {ciphertext}")
