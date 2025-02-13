import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import cv2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import webbrowser


# Function to encrypt a message using AES
def encrypt_message(message, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext  # Concatenate IV with ciphertext for decryption


# Function to decrypt the message using AES
def decrypt_message(encrypted_data, key):
    iv = encrypted_data[:16]  # Extract IV
    ciphertext = encrypted_data[16:]  # Extract actual ciphertext
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode('utf-8')


# Function to hide the encrypted message in a text file using zero-width characters
def hide_message_in_text(file_path, encrypted_message):
    binary_data = ''.join(format(byte, '08b') for byte in encrypted_message)
    zero_width_chars = {'0': '\u200b', '1': '\u200c'}  # Zero-width characters

    # Convert binary data to zero-width characters
    hidden_data = ''.join(zero_width_chars[bit] for bit in binary_data)

    # Append hidden data to the input text
    with open(file_path, 'r', encoding='utf-8') as file:
        text = file.read()

    # Add hidden data at the end
    modified_text = text + hidden_data

    # Save the modified text with UTF-8 encoding
    output_path = os.path.join(os.path.dirname(file_path), "hidden_message_output.txt")
    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(modified_text)

    return output_path


# Function to extract the hidden message from text
def extract_hidden_message(file_path):
    zero_width_chars = {'\u200b': '0', '\u200c': '1'}
    with open(file_path, 'r', encoding='utf-8') as file:
        text = file.read()

    # Extract zero-width characters from the text
    hidden_data = ''.join(char for char in text if char in zero_width_chars)

    # Convert zero-width characters back to binary
    binary_data = ''.join(zero_width_chars[char] for char in hidden_data)

    # Convert binary data back to bytes
    encrypted_message = bytes(int(binary_data[i:i + 8], 2) for i in range(0, len(binary_data), 8))
    return encrypted_message


# GUI Application Class
class TextSteganographyApp:
    def __init__(self, root, video_path):
        self.root = root
        self.root.title("Text Steganography")
        self.root.geometry("2000x800")
        self.root.state("zoomed")  # Adjust window size for zoomed effect

        # Initialize OpenCV video capture
        self.video_capture = cv2.VideoCapture(video_path)

        self.canvas = tk.Canvas(self.root, width=1280, height=800, bg="black")
        self.canvas.pack(side="left", fill="both", expand=True)  # Video occupies the left

        # Create a frame for the buttons and labels (right side)
        self.frame = tk.Frame(self.root, bg="#f0f0f0", width=320)
        self.frame.pack(side="right", fill="y")  
        # Start the video playback loop
        self.play_video()

        # Create the main page
        self.create_main_page()

    def play_video(self):
        ret, frame = self.video_capture.read()
        if ret:
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frame = cv2.resize(frame, (2000, 900))
            self.photo = ImageTk.PhotoImage(image=Image.fromarray(frame))
            self.canvas.create_image(0, 0, image=self.photo, anchor="nw")
        else:
            # Restart video if it ends
            self.video_capture.set(cv2.CAP_PROP_POS_FRAMES, 0)

        self.root.after(10, self.play_video)

    def clear_widgets(self):
        for widget in self.root.winfo_children():
            if widget != self.canvas:
                widget.destroy()

    def create_main_page(self):
        self.clear_widgets()

        frame = tk.Frame(self.root, bg="#f0f0f0", bd=2, relief="ridge")
        frame.place(relx=0.7, rely=0.5, anchor="center", width=600, height=600)

        tk.Label(frame, text="Text Steganography", font=("Arial", 20, "bold"), bg="#f0f0f0").pack(pady=20)

        # Encrypt and Decrypt buttons
        tk.Button(frame, text="Encrypt and Hide", width=20, height=2, bg="#4CAF50", fg="white", font=("Arial", 14),
                  command=self.encrypt_page).pack(pady=10)

        tk.Button(frame, text="Decrypt and Extract", width=20, height=2, bg="#2196F3", fg="white", font=("Arial", 14),
                  command=self.decrypt_page).pack(pady=10)

        tk.Button(frame, text="Back", width=20, height=2, bg="#F44336", fg="white", font=("Arial", 14),
                  command=self.open_index_html).pack(pady=20)

    def open_index_html(self):
        webbrowser.open("http://127.0.0.1:5000/index")

    def encrypt_page(self):
        self.clear_widgets()

        frame = tk.Frame(self.root, bg="#f0f0f0", bd=2, relief="ridge")
        frame.place(relx=0.7, rely=0.5, anchor="center", width=800, height=600)

        tk.Label(frame, text="Encrypt and Hide Message", font=("Arial", 24, "bold"), bg="#f0f0f0").pack(pady=30)

        tk.Label(frame, text="Browse Text File:", bg="#f0f0f0", font=("Arial", 14)).pack()
        file_path_entry = tk.Entry(frame, width=50, font=("Arial", 18))
        file_path_entry.pack(pady=10)
        tk.Button(frame, text="Browse", bg="#FFC107", font=("Arial", 14),
                  command=lambda: file_path_entry.insert(0, filedialog.askopenfilename())).pack(pady=10)

        tk.Label(frame, text="Enter Message to Hide:", bg="#f0f0f0", font=("Arial", 14)).pack()
        message_entry = tk.Entry(frame, width=50, font=("Arial", 18))
        message_entry.pack(pady=10)

        tk.Label(frame, text="Enter Key (16, 24, or 32 chars):", bg="#f0f0f0", font=("Arial", 14)).pack()
        key_entry = tk.Entry(frame, width=50, font=("Arial", 18), show="*")
        key_entry.pack(pady=10)

        def encrypt_and_hide():
            file_path = file_path_entry.get()
            message = message_entry.get()
            key = key_entry.get()

            if not file_path or not message or not key:
                messagebox.showerror("Error", "All fields are required!")
                return
            if len(key) not in [16, 24, 32]:
                messagebox.showerror("Error", "Key must be 16, 24, or 32 characters long!")
                return

            try:
                encrypted_message = encrypt_message(message, key)
                output_path = hide_message_in_text(file_path, encrypted_message)
                messagebox.showinfo("Success", f"Message hidden successfully!\nOutput File: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(frame, text="Encrypt and Hide", bg="#4CAF50", fg="white", font=("Arial", 16),
                  command=encrypt_and_hide).pack(pady=20)
        tk.Button(frame, text="Back", bg="#F44336", fg="white", font=("Arial", 16), command=self.create_main_page).pack(
            pady=20)

    def decrypt_page(self):
        self.clear_widgets()

        frame = tk.Frame(self.root, bg="#f0f0f0", bd=2, relief="ridge")
        frame.place(relx=0.7, rely=0.5, anchor="center", width=800, height=600)

        tk.Label(frame, text="Decrypt and Extract Message", font=("Arial", 24, "bold"), bg="#f0f0f0").pack(pady=30)

        tk.Label(frame, text="Browse File with Hidden Message:", bg="#f0f0f0", font=("Arial", 14)).pack()
        file_path_entry = tk.Entry(frame, width=50, font=("Arial", 14))
        file_path_entry.pack(pady=10)
        tk.Button(frame, text="Browse", bg="#FFC107", font=("Arial", 14),
                  command=lambda: file_path_entry.insert(0, filedialog.askopenfilename())).pack(pady=10)

        tk.Label(frame, text="Enter Key (16, 24, or 32 chars):", bg="#f0f0f0", font=("Arial", 14)).pack()
        key_entry = tk.Entry(frame, width=50, font=("Arial", 18), show="*")
        key_entry.pack(pady=10)

        def decrypt_and_extract():
            file_path = file_path_entry.get()
            key = key_entry.get()

            if not file_path or not key:
                messagebox.showerror("Error", "All fields are required!")
                return
            if len(key) not in [16, 24, 32]:
                messagebox.showerror("Error", "Key must be 16, 24, or 32 characters long!")
                return

            try:
                encrypted_data = extract_hidden_message(file_path)
                message = decrypt_message(encrypted_data, key)
                messagebox.showinfo("Decrypted Message", f"Message: {message}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(frame, text="Decrypt and Extract", bg="#2196F3", fg="white", font=("Arial", 16),
                  command=decrypt_and_extract).pack(pady=20)
        tk.Button(frame, text="Back", bg="#F44336", fg="white", font=("Arial", 16), command=self.create_main_page).pack(
            pady=20)


# Main Program
if __name__ == "__main__":
    video_path = r"C:\Users\thont\OneDrive\Desktop\stegno\finalbackground.mp4" # Replace with your video file path
    root = tk.Tk()
    app = TextSteganographyApp(root, video_path)
    root.mainloop()
