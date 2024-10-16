import tkinter as tk
from tkinter import messagebox, filedialog
import pyperclip
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64

# Function to generate RSA keys and encrypt a message
def rsa_encrypt(message):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return private_key, ciphertext

# Function to decrypt a message using RSA
def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return plaintext

# Function to sign data using RSA
def rsa_sign(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

# Function to generate DH parameters and keys
def dh_key_exchange():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Function to generate ECC key pair and sign a message
def ecc_sign(data):
    private_key = ec.generate_private_key(curve=ec.SECP256R1(), backend=default_backend())
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return private_key, signature

# GUI Functions
def encrypt_message():
    message = entry_message.get().encode()
    if not message:
        messagebox.showerror("Input Error", "Please enter a message to encrypt.")
        return
    
    private_key, ciphertext = rsa_encrypt(message)
    global rsa_private_key
    rsa_private_key = private_key
    label_encrypted.config(text=f"Encrypted: {base64.b64encode(ciphertext).decode()}")

def decrypt_message():
    encrypted_message = entry_decrypt.get()
    if not encrypted_message or 'rsa_private_key' not in globals():
        messagebox.showerror("Input Error", "Please enter an encrypted message or no private key available.")
        return

    try:
        ciphertext = base64.b64decode(encrypted_message)
        decrypted_message = rsa_decrypt(rsa_private_key, ciphertext)
        messagebox.showinfo("Decrypted Message", f"Decrypted: {decrypted_message.decode()}")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def copy_to_clipboard():
    encrypted_text = label_encrypted.cget("text").replace("Encrypted: ", "")
    pyperclip.copy(encrypted_text)
    messagebox.showinfo("Copied", "Encrypted message copied to clipboard!")

def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    with open(file_path, 'rb') as file:
        file_data = file.read()

    private_key, ciphertext = rsa_encrypt(file_data)
    global rsa_private_key
    rsa_private_key = private_key

    encrypted_file_path = f"Enc_{file_path.split('/')[-1]}.enc"
    with open(encrypted_file_path, 'wb') as file:
        file.write(ciphertext)

    messagebox.showinfo("File Encrypted", f"Encrypted file saved as: {encrypted_file_path}")

def decrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    try:
        decrypted_data = rsa_decrypt(rsa_private_key, encrypted_data)
        decrypted_file_path = f"Dec_{file_path.split('/')[-1].replace('.enc', '')}"
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)

        messagebox.showinfo("File Decrypted", f"Decrypted file saved as: {decrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def perform_dh():
    private_key, public_key = dh_key_exchange()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    messagebox.showinfo("DH Public Key", f"Public Key:\n{public_key_bytes}")

def show_ecc_options():
    messagebox.showinfo("ECC Options", "ECC functionalities not implemented yet.")

def show_rsa_options():
    clear_menu()
    tk.Button(menu_frame, text="Encrypt Message", command=encrypt_message).grid(row=0, column=0, padx=5)
    tk.Button(menu_frame, text="Decrypt Message", command=decrypt_message).grid(row=0, column=1, padx=5)
    tk.Button(menu_frame, text="Encrypt File", command=encrypt_file).grid(row=1, column=0, padx=5)
    tk.Button(menu_frame, text="Decrypt File", command=decrypt_file).grid(row=1, column=1, padx=5)
    tk.Button(menu_frame, text="Back", command=show_main_menu).grid(row=1, column=2, padx=5)

def clear_menu():
    for widget in menu_frame.winfo_children():
        widget.grid_forget()

def show_main_menu():
    clear_menu()
    tk.Button(menu_frame, text="RSA", command=show_rsa_options).grid(row=0, column=0, padx=5)
    tk.Button(menu_frame, text="ECC", command=show_ecc_options).grid(row=0, column=1, padx=5)
    tk.Button(menu_frame, text="DH", command=perform_dh).grid(row=0, column=2, padx=5)

# Main GUI Setup
root = tk.Tk()
root.title("Cryptography GUI")

# Menu for techniques
menu_frame = tk.Frame(root)
menu_frame.grid(row=0, column=0, columnspan=4, pady=10)

show_main_menu()  # Show the main menu on startup

# Entry for Message
tk.Label(root, text="Enter Message:").grid(row=1, column=0, pady=10, sticky="w")
entry_message = tk.Entry(root, width=50)
entry_message.grid(row=1, column=1, pady=10)

# Entry for Encrypted Message
tk.Label(root, text="Enter Encrypted Message:").grid(row=2, column=0, pady=10, sticky="w")
entry_decrypt = tk.Entry(root, width=50)
entry_decrypt.grid(row=2, column=1, pady=10)

# Label to show encrypted message
tk.Label(root, text="Encrypted Message:").grid(row=3, column=0, pady=10, sticky="w")
label_encrypted = tk.Label(root, text="")
label_encrypted.grid(row=3, column=1, pady=10)

# Copy to Clipboard button
tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard).grid(row=4, column=0, pady=5)

# Close button
tk.Button(root, text="Close", command=root.quit).grid(row=4, column=1, pady=5)

root.mainloop()
