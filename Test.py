import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Function to derive a key from the password
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_message(message, key):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    try:
        cipher = Fernet(key)
        decrypted_message = cipher.decrypt(encrypted_message).decode()
        return decrypted_message
    except InvalidToken:
        return "Invalid password or message"

def encrypt():
    global encryption_password, salt
    message = message_entry.get("1.0", "end-1c")
    password = password_entry.get()
    if message and password:
        salt = os.urandom(16)  # Generate a new salt
        encryption_password = password  # Store encryption password
        key = derive_key(password, salt)
        encrypted_message = encrypt_message(message, key)
        encrypted_message_entry.delete("1.0", "end")
        encrypted_message_entry.insert("1.0", base64.urlsafe_b64encode(salt + encrypted_message).decode())
    else:
        messagebox.showerror("Error", "Please enter both message and password.")

def decrypt():
    encrypted_message = encrypted_message_entry.get("1.0", "end-1c")
    check = password_entry.get()
    global encryption_password, salt
    if encrypted_message and check:
        encrypted_message = base64.urlsafe_b64decode(encrypted_message.encode())
        salt = encrypted_message[:16]  # Extract the salt from the encrypted message
        encrypted_message = encrypted_message[16:]  # Extract the actual encrypted message
        if check == encryption_password:  # Check if decryption password matches encryption password
            key = derive_key(check, salt)
            decrypted_message = decrypt_message(encrypted_message, key)
            if decrypted_message:
                result_text.set("Decrypted message: " + decrypted_message)
            else:
                messagebox.showerror("Error", "Decryption failed. Incorrect password or key.")
        else:
            messagebox.showerror("Error", "Invalid password")
    else:
        messagebox.showerror("Error", "Please enter both encrypted message and password.")

def reset():
    message_entry.delete("1.0", "end")
    password_entry.delete(0, "end")
    encrypted_message_entry.delete("1.0", "end")
    result_text.set("")

def quit_app():
    root.destroy()

root = tk.Tk()
root.title("SecureText")

message_label = tk.Label(root, text="Message:", fg="black")
message_label.grid(row=0, column=0, sticky="e")
message_entry = scrolledtext.ScrolledText(root, width=30, height=5)
message_entry.grid(row=0, column=1)

password_label = tk.Label(root, text="Password:")
password_label.grid(row=1, column=0, sticky="e")
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=1, column=1)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt, bg="#ed3833", fg="white")
encrypt_button.grid(row=2, column=0)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt, bg="#00bd56", fg="white")
decrypt_button.grid(row=2, column=1)

encrypted_message_label = tk.Label(root, text="Encrypted Message:")
encrypted_message_label.grid(row=3, column=0, sticky="e")
encrypted_message_entry = scrolledtext.ScrolledText(root, width=30, height=5)
encrypted_message_entry.grid(row=3, column=1)

result_text = tk.StringVar()
result_label = tk.Label(root, textvariable=result_text)
result_label.grid(row=4, columnspan=2)

reset_button = tk.Button(root, text="Reset", command=reset, bg="#1089ff", fg="white")
reset_button.grid(row=5, columnspan=2)

quit_button = tk.Button(root, text="Quit", command=quit_app, bg="#D20103", fg="white")
quit_button.grid(row=7, columnspan=2)

root.mainloop()
