from cryptography.fernet import Fernet
import base64
import getpass
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MASTER_PASSWORD_FILE = "master.key"
PASSWORDS_FILE = "passwords.txt"

def generate_key(master_password):
    salt = hashlib.sha256(master_password).digest()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password))
    return key

def encrypt_password(password, key):
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password

def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password).decode()
    return decrypted_password

def view_passwords():
    try:
        with open(MASTER_PASSWORD_FILE, "rb") as file:
            master_password = file.read().decode()
    except FileNotFoundError:
        print("No master password found. Please create a new one.")
        master_password = getpass.getpass("Enter a new master password: ")
        with open(MASTER_PASSWORD_FILE, "wb") as file:
            file.write(master_password.encode())

    key = generate_key(master_password.encode())

    print("Enter your master password to view passwords:")
    entered_password = getpass.getpass()
    if entered_password != master_password:
        print("Invalid master password.")
        return

    try:
        with open(PASSWORDS_FILE, "rb") as file:
            lines = file.readlines()
            if not lines:
                print("No passwords found. Add a password.")
                return

            for line in lines:
                try:
                    account, encrypted_password = line.strip().split(b"|")
                    decrypted_password = decrypt_password(encrypted_password, key)
                    print(f"Account: {account.decode()}, Password: {decrypted_password}")
                except ValueError:
                    print("Error decrypting password.")
    except FileNotFoundError:
        print("No passwords found. Add a password.")

def add_password():
    try:
        with open(MASTER_PASSWORD_FILE, "rb") as file:
            master_password = file.read().decode()
    except FileNotFoundError:
        print("No master password found. Please create a new one.")
        master_password = getpass.getpass("Enter a new master password: ")
        with open(MASTER_PASSWORD_FILE, "wb") as file:
            file.write(master_password.encode())

    key = generate_key(master_password.encode())

    print("Enter your master password to add a new password:")
    entered_password = getpass.getpass()
    if entered_password != master_password:
        print("Invalid master password.")
        return

    account = input("Enter Account Name: ").encode()
    password = getpass.getpass("Enter Password: ")
    encrypted_password = encrypt_password(password, key)
    with open(PASSWORDS_FILE, "ab") as file:
        file.write(account + b"|" + encrypted_password + b"\n")

def main():
    while True:
        print("Would you like to view existing passwords or add a new one? (view, add), press q to quit:")
        choice = input().lower()
        if choice == "q":
            break
        elif choice == "view":
            view_passwords()
        elif choice == "add":
            add_password()
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
