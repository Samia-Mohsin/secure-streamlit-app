# ------- Develop a streamlit-based secure data storage and retrival system.----------
 
import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# ------------------- Constants -------------------
DATA_FILE = "secure_data.json"         # File to store encrypted user data
SALT = b"secure_salt_value"            # Salt value for hashing
LOCKOUT_DURATION = 60                  # Lockout time in seconds after failed login attempts

# ------------------- Session State Initialization -------------------
# Used to persist user state across Streamlit reruns
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0


# ------------------- Utility Functions -------------------

# Load user data from JSON file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save user data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Generate encryption key from passkey using PBKDF2
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

# Hash a user's password securely using PBKDF2 + SHA256
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# Encrypt a plaintext message using Fernet symmetric encryption
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

# Decrypt encrypted text with the corresponding passkey
def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None  # Return None if decryption fails


# ------------------- Load Stored Data -------------------
stored_data = load_data()

# ------------------- Streamlit UI -------------------
st.title("🔐 Secure Data Storage & Retrieval System")

# Navigation menu
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)


# ------------------- Home Page -------------------
if choice == "Home":
    st.subheader("Welcome!")
    st.markdown("""
    This app allows users to securely store and retrieve encrypted text using a passkey.
    Features:
    - User registration/login system
    - Encrypt data with a secret passphrase
    - Decrypt only with the correct key
    - Lockout after multiple failed login attempts
    - Local JSON file-based data storage
    """)

# ------------------- Registration -------------------
elif choice == "Register":
    st.subheader("Register New User")

    # Input fields
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    # Register button
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("User already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("User registered successfully!")
        else:
            st.error("Both fields are required.")

# ------------------- Login -------------------
elif choice == "Login":
    st.subheader("User Login")

    # Check if user is locked out
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    # Login input
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    # Login button
    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining_attempts = 3 - st.session_state.failed_attempts
            st.error(f"Invalid credentials. Attempts left: {remaining_attempts}")

            # Lockout logic after 3 failed attempts
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# ------------------- Store Encrypted Data -------------------
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        st.subheader("Store Encrypted Data")

        # User input
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        # Encrypt and save
        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Data encrypted and saved successfully!")
            else:
                st.error("Both fields are required.")

# ------------------- Retrieve & Decrypt Data -------------------
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        st.subheader("Retrieve Stored Data")

        # Fetch user data
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        # Display encrypted entries
        if not user_data:
            st.info("No data entries found.")
        else:
            st.markdown("### Encrypted Entries")
            for i, item in enumerate(user_data):
                st.code(f"{i + 1}: {item}", language="text")

        # Decrypt input
        encrypted_input = st.text_area("Enter Encrypted Text")
        passkey = st.text_input("Enter Passkey to Decrypt", type="password")

        # Decrypt button
        if st.button("Decrypt"):
            result = decrypt_text(encrypted_input, passkey)
            if result:
                st.success(f"Decrypted: {result}")
            else:
                st.error("Incorrect passkey or corrupted data.")















