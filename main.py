import bcrypt
import pyotp
from cryptography.fernet import Fernet
import os
import json

# Generate encryption key (only run once, store securely)
key_file = "encryption_key.key"

if not os.path.exists(key_file):
    with open(key_file, "wb") as f:
        f.write(Fernet.generate_key())

with open(key_file, "rb") as f:
    encryption_key = f.read()

cipher = Fernet(encryption_key)

db_file = "users.json"

# Initialize user database (JSON file)
if not os.path.exists(db_file):
    with open(db_file, "w") as f:
        json.dump({}, f)

def load_users():
    with open(db_file, "r") as f:
        return json.load(f)

def save_users(users):
    with open(db_file, "w") as f:
        json.dump(users, f)

def register_user(username, password):
    users = load_users()
    if username in users:
        print("Username already exists.")
        return

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    # Generate TOTP secret
    totp_secret = pyotp.random_base32()

    # Encrypt TOTP secret
    encrypted_totp_secret = cipher.encrypt(totp_secret.encode())

    # Store user
    users[username] = {
        "password": hashed_password.decode(),
        "totp_secret": encrypted_totp_secret.decode()
    }

    save_users(users)

    print(f"User registered successfully! Your TOTP secret is: {totp_secret}")
    print("Save this secret in your 2FA app (e.g., Google Authenticator).")

def login_user(username, password):
    users = load_users()
    if username not in users:
        print("Invalid username or password.")
        return

    user = users[username]

    # Verify password
    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        print("Invalid username or password.")
        return

    # Decrypt TOTP secret
    totp_secret = cipher.decrypt(user["totp_secret"].encode()).decode()

    # Verify TOTP
    totp = pyotp.TOTP(totp_secret)
    otp = input("Enter the 6-digit code from your 2FA app: ")
    if not totp.verify(otp):
        print("Invalid 2FA code.")
        return

    print("Login successful!")

# Menu for demonstration purposes
while True:
    print("\n1. Register\n2. Login\n3. Exit")
    choice = input("Choose an option: ")

    if choice == "1":
        username = input("Enter a username: ")
        password = input("Enter a password: ")
        register_user(username, password)
    elif choice == "2":
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        login_user(username, password)
    elif choice == "3":
        break
    else:
        print("Invalid choice. Try again.")
