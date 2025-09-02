import customtkinter as ctk
from tkinterdnd2 import TkinterDnD, DND_FILES
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
from tkinter import messagebox

class Application(ctk.CTkFrame):   
    def __init__(self, master):
        super().__init__(master)
        master.title("🔐File Encryptor and Decryptor")
        self.grid(row=0, column=0, sticky="nsew")  # ✅ Use grid for layout

        # make window expandable
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)

        # ==== Main Label ====
        self.main_label = ctk.CTkLabel(self, text="Encryption and Decryption",
                                       font=("Calibri", 24, "bold"),
                                       text_color="skyblue")
        self.main_label.grid(row=0, column=0, pady=10, sticky="ew")

        # ==== Tabs ====
        self.tabview = ctk.CTkTabview(self, width=480, height=260)
        self.tabview.grid(row=1, column=0, pady=20, sticky="nsew")

        self.encrypt_tab = self.tabview.add("Encrypt")
        self.decrypt_tab = self.tabview.add("Decrypt")

        # ==== Drag & Drop Area in Encrypt tab ====
        self.drop_label_enc = ctk.CTkLabel(self.encrypt_tab, text="Drag & Drop File Here\n\nOR",
                                       fg_color="gray20", corner_radius=10,
                                       width=400, height=100)
        self.drop_label_enc.grid(row=0, column=0, pady=20, padx=20)
        
        # Register Drop
        self.drop_label_enc.drop_target_register(DND_FILES)
        self.drop_label_enc.dnd_bind("<<Drop>>", self.on_file_drop_enc)
        
# ==== Button in encryption tab ====

        self.path_entry = ctk.CTkEntry(self.encrypt_tab,placeholder_text="Enter File Path here")
        self.path_entry.grid(row=2,column=0,sticky="we")
        
        
        self.random_key = ctk.CTkButton(self.encrypt_tab, text="Random Key",command=self.generate_random_key)
        self.random_key.grid(row=4, column=0, pady=10,padx=1,sticky="w")
        
        self.key_entry = ctk.CTkEntry(self.encrypt_tab,placeholder_text="Enter key here")
        self.key_entry.grid(row=3,column=0,padx=(10,5),pady=10,sticky="we")
        
        self.copy_button = ctk.CTkButton(self.encrypt_tab, text = "Copy", command=self.copy_key)
        self.copy_button.grid(row=3,column=1,padx=(5,10), pady=10, sticky="w")
        
        self.encrypt_button = ctk.CTkButton(self.encrypt_tab, text="Encrypt It",command=self.encryption)
        self.encrypt_button.grid(row=4, column=1, columnspan=2,pady=10)
        
        
 # ==== Drag & Drop Area in Decrypt tab =====
        self.drop_label_dec = ctk.CTkLabel(self.decrypt_tab, text="Drag & Drop File Here\n\nOR",
                                         fg_color="gray20", corner_radius=10,
                                         width=400, height=100)
        self.drop_label_dec.grid(row=0, column=0, pady=20, padx=20)

        # Register Drop
        self.drop_label_dec.drop_target_register(DND_FILES)
        self.drop_label_dec.dnd_bind("<<Drop>>", self.on_file_drop_dec)
        
        self.dec_file_entry = ctk.CTkEntry(self.decrypt_tab,placeholder_text="Enter File Path here")
        self.dec_file_entry.grid(row=1,column=0,sticky="we")
        
        self.key_entry_dec = ctk.CTkEntry(self.decrypt_tab,placeholder_text="Enter key here")
        self.key_entry_dec.grid(row=3,column=0,padx=(10,5),pady=10,sticky="we")
        
        self.paste_button_dec = ctk.CTkButton(self.decrypt_tab, text="Paste",command=self.paste_text)
        self.paste_button_dec.grid(row=3,column=1,padx=(5,10),pady=10,sticky="w")
        
        self.decrypt_button = ctk.CTkButton(self.decrypt_tab, text="Decrypt It", command=self.decryption)
        self.decrypt_button.grid(row=4, column=1, pady=10)
        

    def on_file_drop_enc(self, event):
        self.file_path_enc = event.data.strip("{}")  
        self.drop_label_enc.configure(text=f"Dropped: {self.file_path_enc}")
    
    def on_file_drop_dec(self, event):
        self.file_path_dec = event.data.strip("{}")  
        self.drop_label_dec.configure(text=f"Dropped: {self.file_path_dec}")
    
    def generate_random_key(self):
        self.key = get_random_bytes(16)
        self.key_entry.delete(0,"end")
        self.key_entry.insert(0,self.key.hex())
    
    def copy_key(self):
        entry_key = self.key_entry.get()
        self.master.clipboard_clear()
        self.master.clipboard_append(entry_key)
        self.master.update()
    
    def paste_text(self):
        try:
            text = self.clipboard_get()
            self.key_entry_dec.delete(0, "end")
            self.key_entry_dec.insert(0, text)
            
        except:
            pass
    
    def encryption(self):
        entry_file_path = self.path_entry.get().strip().replace("\\","/")
        if entry_file_path:
            file_path = entry_file_path
        elif hasattr(self, "file_path_enc"):
            file_path = self.file_path_enc
        else:
            messagebox.showerror("File Error","No file selected for encryption")
            return
        
        if not os.path.isfile(file_path):
            messagebox.showerror("File Error",f"File does not exist:\n{file_path}")
            return
        
        try:
            with open(file_path,'rb') as f:
                data = f.read()
        except AttributeError:
            messagebox.showerror("File Error","No file selected for encryption!")
            return
        try:
            cipher = AES.new(self.key, AES.MODE_CBC)
            iv = cipher.iv
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
        except Exception as e:
            messagebox.showerror("Encryption Error",f"Encryption failed:\n{str(e)}")
            return
        
        folder = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
        
        enc_file_path = os.path.join(folder, filename + ".enc")
        
        try:
            with open(enc_file_path, 'wb') as f:
                f.write(iv + cipher_text)
            messagebox.showinfo("Sucess",f"file encrypted successfully!\nSaved as {enc_file_path}")
        except Exception as e:
            messagebox.showerror("File Error",f"Failed to save encrypted file:\n{str(e)}")   
        
        try:
            os.remove(file_path)
        except PermissionError:
            print("Permission denied! Cannot delete the file.")
            
        
            
    def decryption(self):
        entry_file_path = self.dec_file_entry.get().strip().replace("\\",'/')
        
        if entry_file_path:
            file_path = entry_file_path
        elif hasattr(self, "file_path_ene"):
            file_path = self.file_path_enc
        else:
            messagebox.showerror("File Error", "No file selected for encryptin!")
            return
        
        if not os.path.isfile(file_path):
            messagebox.showerror("File Error",f"File does not exist:\n{file_path}")
            return
        
        try:
            self.key_dec = bytes.fromhex(self.key_entry_dec.get())
        except ValueError:
            messagebox.showerror("Invalid Key", "Please enter a valid hex key!")
            return
        
        try:
            with open(file_path,'rb') as f:
                file_data = f.read()
        except AttributeError:
            messagebox.showerror("File Error", f"Failed to read file:\n{str(e)}")
            return
        
        try:
            cipher_text = file_data[16:]
            iv = file_data[:16]
        except Exception:
            messagebox.showerror("File Error", "Encrypted file is corrupted or invalid!")
            return
            
        try:
            cipher = AES.new(self.key_dec,AES.MODE_CBC,iv)
            plain_text = unpad(cipher.decrypt(cipher_text),AES.block_size)
        except ValueError:
            messagebox.showerror("Decryption failed", "Wrong key or corrupted file.")
            return
            
        folder = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
        name_only, ext = os.path.splitext(filename)
        dec_file_path = os.path.join(folder,name_only)
        
        try:
            with open(dec_file_path,'wb') as f:
                f.write(plain_text)
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as {dec_file_path}")
        except Exception as e:
            messagebox.showerror("File Error", f"Failed to save decrypted file:\n{str(e)}")
        
        try:
            os.remove(file_path)
        except PermissionError:
            messagebox.showerror("Permission denied! Cannot delete the file.")  
            

root = TkinterDnD.Tk()
app = Application(root)
root.mainloop()