from tkinter import *
from tkinter import messagebox
from PIL import ImageTk, Image
import base64

screen = Tk()
screen.config(padx=50, pady=50)
screen.title("Secret Notes")

#apply cryptography with vigenere ciphher
#https://stackoverflow.com/a/38223403

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_encrypt():
    _text = text.get("1.0", "end-1c")
    title = entry.get()
    masterkey_text = master_key.get()

    if len(_text) == 0 or len(title) == 0 or len(masterkey_text) == 0:
        messagebox.showwarning("Warning", "Please enter all information")
    else:
        encrypted_text = encode(masterkey_text, _text)
        try:
            title_file = open("SecretNotes.txt", "a")
            title_file.write(title + "\n")
            text_file = open("SecretNotes.txt", "a")
            text_file.write(encrypted_text + "\n" + "-" * 70 + "\n")
        except FileNotFoundError:
            with open("SecretNotes.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{encrypted_text}')
        finally:
            master_key.delete(0, END)
            text.delete("1.0", "end")
            entry.delete(0, "end")



def decrypt():
    decrypt = text.get("1.0", "end-1c")
    masterkey_text = master_key.get()

    if len(decrypt) == 0 or len(masterkey_text) == 0:
        messagebox.showwarning("Warning", "Please enter all information")
    else:
        try:
            decrypted_text = decode(masterkey_text, decrypt)
            text.delete("1.0", "end")
            text.insert("1.0", decrypted_text)
        except:
            messagebox.showerror("Error!", "Please enter encrypted text")

#ui

img = ImageTk.PhotoImage(Image.open("top_secret.png"))
panel = Label(image = img)
panel.pack()

entry_label = Label(text="Enter your title")
entry_label.pack()
entry = Entry(width=30)
entry.pack()

text_label = Label(text="Enter your secret")
text_label.pack()
text = Text(width=45, height=15)
text.pack()

master_key_label = Label(text="Enter master key")
master_key_label.pack()
master_key = Entry(width=30)
master_key.pack()

save_encrypt_button = Button(text="Save & Encrypt", command=save_encrypt)
save_encrypt_button.pack()

decrypt_button = Button(text="Decrypt", command=decrypt)
decrypt_button.pack()

screen.mainloop()