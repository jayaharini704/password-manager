# Password Manager

Password Manager is a secure command-line application written in Python that allows users to store and manage their passwords with encryption. The program uses a master password to unlock and access the stored passwords. Users can add new passwords, view existing ones, and ensure their sensitive information remains protected through encryption techniques.

## Features

- Store and manage passwords securely
- Encrypt passwords using Fernet encryption
- User-friendly command-line interface
- Master password protection for added security

## How to Use

1. Clone this repository to your local machine.
2. Make sure you have Python installed (Python 3.6 or above).
3. Install the required dependencies by running `pip install -r requirements.txt`.
4. Run the `password_manager.py` script to start the password manager.
5. If you are using the password manager for the first time, it will prompt you to set a master password.
6. Choose from the available options to add new passwords or view existing ones.
7. When viewing passwords, you will be asked to enter the master password for verification.

## Dependencies

The Password Manager uses the following Python libraries:

- cryptography

## Note

It is essential to remember your master password as it cannot be recovered if forgotten. Make sure to keep your master password secure and do not share it with others.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
