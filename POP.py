#Ik wou ook nog heel graag de vault beschermen maar hiervoor heb ik geen goede manier gevonden. Eerst dacht ik de vault
#te beschermen met een wachtwoord zoals bij administrator progamma's maar blijkbaar kan Python dit niet doen.
#Ik heb nog even verder gezocht naar andere opties maar ze zeiden allemaal dat Python het niet kan doen.

import string
import random
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
import base64
import tkinter as tk
from os.path import exists

def is_checked():
    chars = list(string.ascii_lowercase)
    if cb_cl.get() == "y":
        chars += list(string.ascii_uppercase)
    if cb_nm.get() == "y":
        chars += list(string.digits)
    if cb_sc.get() == "y":
        chars += list("!@#$%^&*()")

    return chars


def generate_password(size):
    global password
    generated_list = []

    characters = is_checked()
    for i in range(size):
        generated_list.append(random.choice(characters))
    random.shuffle(generated_list)
    password = "".join(generated_list)
    password_field.config(text=password)


def encrypt(text, key, website_name):
    text = base64.b64encode(text.encode("utf-8"))
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    scrambled = cipher.encrypt(pad(text, AES.block_size))
    write_to_doc(iv + scrambled, key, website_name)


def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    unscrambled = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    decrypted_field.config(text=base64.b64decode(unscrambled).decode("utf-8"))


def write_to_doc(iv_scrambled, private_key, website):
    global counter
    f_password = Fernet(password_key)
    f_encrypted_password = f_password.encrypt(iv_scrambled)
    f_private_key = Fernet(private_key_key)
    f_encrypted_private_key = f_private_key.encrypt(private_key)
    with open("password.txt", "a+") as file:
        file.write(str(counter) + "," + website + "," + base64.b64encode(f_encrypted_password).decode("utf-8") + "\n")
    with open("private_key.txt", "a+") as file1:
        file1.write(str(counter) + "," + base64.b64encode(f_encrypted_private_key).decode("utf-8") + "\n")
    counter += 1
    options.append(website)
    name = website
    refresh(name)


def read_from_doc(choice):
    f_password = Fernet(password_key)
    f_private_key = Fernet(private_key_key)
    with open("password.txt", "r") as file:
        file.readline()
        for line in file:
            number, name, iv_scrambled_encrypted = line.rstrip().split(",")
            if choice == name:
                iv_scrambled = f_password.decrypt(base64.b64decode(iv_scrambled_encrypted.encode("utf-8")))
                choice = number
    with open("private_key.txt", "r") as file1:
        for line in file1:
            if choice == line[0]:
                number, private_key_scrambled = line.rstrip().split(",")
                private_key = f_private_key.decrypt(base64.b64decode(private_key_scrambled.encode("utf-8")))
    decrypt(iv_scrambled, private_key)


def refresh(website):
    options.append(website)
    menu = options_menu.children["menu"]
    menu.add_command(label=website, command=tk._setit(value, website))

master_password = "123"
password_check = input("Master password: ")
if master_password == password_check:
    password = ""
    counter = 1
    password_key = b''
    private_key_key = b''
    options = []

    if exists("password.txt"):
        with open("password.txt", "r") as file:
            options.append(file.readline().rstrip())
            for line in file:
                number, name, remainder = line.split(",")
                options.append(name)
                counter += 1
    else:
        with open("password.txt", "w") as file:
            file.write("Select a website\n")
            options.append("Select a website")
    if not exists("private_key.txt"):
        with open("private_key.txt", "w") as file:
            pass
    if not exists("key_file.txt"):
        password_key = Fernet.generate_key().decode("utf-8")
        private_key_key = Fernet.generate_key().decode("utf-8")
        with open("key_file.txt", "w") as mykey:
            mykey.write(password_key + "\n")
            mykey.write(private_key_key)
    else:
        with open("key_file.txt", "r") as file:
            lines = file.readlines()
            password_key = lines[0].rstrip().encode("utf-8")
            private_key_key = lines[1].encode("utf-8")

    window = tk.Tk()
    window.title("Password Manager")
    window.config(padx=50, pady=50)

    password_text = tk.Label(window, text="Generated password")
    password_text.grid(row=0, column=0, sticky="w")
    password_field = tk.Label(window, width=40, background="white")
    password_field.grid(row=0, column=1, columnspan=3)

    spacing_row1 = tk.Label(window)
    spacing_row1.grid(row=1)
    window.rowconfigure(1, minsize=5)

    cb_cl = tk.StringVar(value="n")
    cb_nm = tk.StringVar(value="n")
    cb_sc = tk.StringVar(value="n")

    options_text = tk.Label(window, text="Options")
    options_text.grid(row=2, column=0, sticky="w")
    capital_letters = tk.Checkbutton(window, text="Capital letters", variable=cb_cl, onvalue="y", offvalue="n")
    capital_letters.grid(row=2, column=1)
    numbers = tk.Checkbutton(window, text="Digits", variable=cb_nm, onvalue="y", offvalue="n")
    numbers.grid(row=2, column=2)
    special_chars = tk.Checkbutton(window, text="Special characters", variable=cb_sc, onvalue="y", offvalue="n")
    special_chars.grid(row=2, column=3)

    spacing_row2 = tk.Label(window)
    spacing_row2.grid(row=3)
    window.rowconfigure(3, minsize=5)

    length_text = tk.Label(window, text="Password length")
    length_text.grid(row=4, column=0, sticky="w")
    password_length = tk.Entry(window, width=40)
    password_length.grid(row=4, column=1, columnspan=3)

    spacing_row3 = tk.Label(window)
    spacing_row3.grid(row=1)
    window.rowconfigure(5, minsize=5)

    name_text = tk.Label(window, text="Name of website")
    name_text.grid(row=6, column=0, sticky="w")
    name = tk.Entry(window, width=40)
    name.grid(row=6, column=1, columnspan=3)

    spacing_row4 = tk.Label(window)
    spacing_row4.grid(row=7)
    window.rowconfigure(7, minsize=10)

    generate_button = tk.Button(window, text="Generate password",
                                command=lambda: generate_password(int(password_length.get())))
    generate_button.grid(row=8, column=0, columnspan=1)

    encrypt_password = tk.Button(window, text="Save password",
                                 command=lambda: encrypt(password, Random.get_random_bytes(32), name.get()))
    encrypt_password.grid(row=8, column=1, columnspan=1)

    spacing_row5 = tk.Label(window)
    spacing_row5.grid(row=9)
    window.rowconfigure(9, minsize=10)

    value = tk.StringVar(window)
    value.set(options[0])
    options_menu = tk.OptionMenu(window, value, *options)
    options_menu.grid(row=10, column=0)
    decrypt_password = tk.Button(window, text="Load password", command=lambda: read_from_doc(value.get()))
    decrypt_password.grid(row=10, column=1, columnspan=1)
    decrypted_field = tk.Label(window, width=40, background="white")
    decrypted_field.grid(row=11, column=0, columnspan=3)

    window.mainloop()
else:
    exit()