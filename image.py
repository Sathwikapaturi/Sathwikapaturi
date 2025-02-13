from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter.filedialog import askopenfilename
from PIL import Image, ImageTk
import cv2
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import webbrowser

class Stegno:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Data Encryptor/Decryptor")
        self.root.geometry("1920x1080")
        self.root.state("zoomed")

        self.video_source = r"C:\\Users\\thont\\OneDrive\\Desktop\\stegno\\finalbackground.mp4"
        self.cap = cv2.VideoCapture(self.video_source)
        self.canvas = Canvas(self.root, width=1920, height=1080)
        self.canvas.pack(fill=BOTH, expand=True)

        self.update_background()
        self.main_menu()

    def update_background(self):
        ret, frame = self.cap.read()
        if ret:
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frame = cv2.resize(frame, (2000, 900))
            frame_image = ImageTk.PhotoImage(Image.fromarray(frame))
            self.canvas.create_image(0, 0, anchor=NW, image=frame_image)
            self.canvas.image = frame_image

        self.root.after(10, self.update_background)

    def main_menu(self):
        self.clear_screen()
        frame = Frame(self.root, width=500, height=400, bg="white")
        frame.place(relx=0.7, rely=0.5, anchor="center")
        frame.grid_propagate(False)  
  

        # Title: Centered at the top
        title = Label(frame, text='Image Steganography', fg="black", font=('Helvetica', 24, 'bold'), bg="white")
        title.grid(row=0, column=0, columnspan=2, pady=20, sticky="nsew")

        # Buttons: Encode and Decode side by side
        Button(frame, text="Encode", command=lambda: self.encode_screen(), padx=14, pady=8, bd=5, relief="raised",
               bg="#2980B9", fg="white", font=('Helvetica', 16, 'bold')).grid(row=1, column=0, padx=20, pady=10)

        Button(frame, text="Decode", command=lambda: self.decode_screen(), padx=14, pady=8, bd=5, relief="raised",
               bg="#27AE60", fg="white", font=('Helvetica', 16, 'bold')).grid(row=1, column=1, padx=20, pady=10)

        # Back button: Centered below the other buttons
        Button(frame, text="BACK", command=self.open_index_page, padx=14, pady=8, bd=5, relief="raised",
               bg="#E74C3C", fg="white", font=('Helvetica', 16, 'bold')).grid(row=2, column=0, columnspan=2, pady=20)

        # Configure grid weights for centering
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_rowconfigure(2, weight=1)
    def clear_screen(self):
        for widget in self.root.winfo_children():
            if not isinstance(widget, Canvas):
                widget.destroy()

    def open_index_page(self):
        webbrowser.open("http://127.0.0.1:5000/index")

    def encode_screen(self):
        self.clear_screen()
        frame = Frame(self.root, width=1000, height=1000, bg="white")
        frame.place(relx=0.7, rely=0.5, anchor="center")
        frame.grid_propagate(False)


        Label(frame, text='Select the image to hide the message:', fg="black", font=('Helvetica', 16), bg="white").pack(pady=10)

        Button(frame, text='Select', command=lambda: self.load_image(frame), padx=14, pady=8, bd=5, relief="raised", \
               bg="#F39C12", fg="white", font=('Helvetica', 14)).pack(pady=10)

        Button(frame, text='Back', command=self.main_menu, padx=14, pady=8, bd=5, relief="raised", bg="#E74C3C", \
               fg="white", font=('Helvetica', 14)).pack(pady=10)

    def load_image(self, parent_frame):
        file_path = askopenfilename(filetypes=[('Image Files', '.png;.jpeg;*.jpg')])
        if not file_path:
            messagebox.showerror("Error", "No file selected")
            return

        image = Image.open(file_path)
        self.show_encode_options(parent_frame, image, file_path)

    def show_encode_options(self, parent_frame, image, file_path):
        parent_frame.destroy()

        frame = Frame(self.root, bg="white")
        frame.place(relx=0.7, rely=0.5, anchor="center")

        img = ImageTk.PhotoImage(image.resize((300, 200)))
        Label(frame, image=img, bg="white").image = img  # Keep reference
        Label(frame, image=img, bg="white").pack(pady=10)

        Label(frame, text='Enter the message to hide:', fg="black", font=('Helvetica', 16), bg="white").pack(pady=10)
        text_area = Text(frame, width=40, height=4, font=('Helvetica', 12))
        text_area.pack()

        Label(frame, text="Enter Secret Key (16 characters):", fg="black", font=('Helvetica', 16), bg="white").pack(pady=10)
        secret_key = Entry(frame, font=('Helvetica', 14), show="*")
        secret_key.pack(pady=10)

        Button(frame, text='Encode', command=lambda: self.encode_message(image, text_area.get("1.0", "end-1c"), \
               secret_key.get(), file_path), padx=14, pady=8, bd=5, relief="raised", bg="#2980B9", fg="white", \
               font=('Helvetica', 14)).pack(pady=10)

        Button(frame, text='Back', command=self.main_menu, padx=14, pady=8, bd=5, relief="raised", bg="#E74C3C", \
               fg="white", font=('Helvetica', 14)).pack(pady=10)

    def encode_message(self, image, message, key, file_path):
        if len(message) == 0 or len(key) != 16:
            messagebox.showerror("Error", "Please provide a valid message and a 16-character key")
            return

        encrypted_data = self.encrypt_data(message, key)
        self.embed_data(image, encrypted_data, file_path)

    def encrypt_data(self, message, key):
        cipher = Cipher(algorithms.AES(key.encode()), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(encrypted_data).decode()

    def embed_data(self, image, data, file_path):
        data += "#####"
        binary_data = ''.join([format(ord(char), '08b') for char in data])
        pixels = image.load()
        data_index = 0

        for y in range(image.height):
            for x in range(image.width):
                pixel = list(pixels[x, y])
                for i in range(3):
                    if data_index < len(binary_data):
                        pixel[i] = (pixel[i] & ~1) | int(binary_data[data_index])
                        data_index += 1
                pixels[x, y] = tuple(pixel)
                if data_index >= len(binary_data):
                    break

        save_path = os.path.join(os.path.dirname(file_path), "encoded_image.png")
        image.save(save_path)
        messagebox.showinfo("Success", f"Message successfully encoded and saved as '{save_path}'")
        self.main_menu()

    def decode_screen(self):
        self.clear_screen()
        frame = Frame(self.root, width=1000, height=1000, bg="white")
        frame.place(relx=0.7, rely=0.5, anchor="center")
        frame.grid_propagate(False)

        Label(frame, text='Select the encoded image to decode:', fg="black", font=('Helvetica', 20), bg="white").pack(pady=10)

        Button(frame, text='Select', command=self.decode_message, padx=14, pady=8, bd=5, relief="raised", bg="#F39C12", \
               fg="white", font=('Helvetica', 14)).pack(pady=10)

        Button(frame, text='Back', command=self.main_menu, padx=14, pady=8, bd=5, relief="raised", bg="#E74C3C", \
               fg="white", font=('Helvetica', 14)).pack(pady=10)

    def decode_message(self):
        file_path = askopenfilename(filetypes=[('Image Files', '.png;.jpeg;*.jpg')])
        if not file_path:
            messagebox.showerror("Error", "No file selected")
            return

        image = Image.open(file_path)
        hidden_data = self.extract_data(image)
        if hidden_data:
            self.show_decrypt_screen(hidden_data, image)
        else:
            messagebox.showerror("Error", "No hidden message found")

    def show_decrypt_screen(self, hidden_data, image):
        self.clear_screen()

        frame = Frame(self.root, bg="white")
        frame.place(relx=0.7, rely=0.5, anchor="center")

    # Show the selected image
        img = ImageTk.PhotoImage(image.resize((300, 200)))
        Label(frame, image=img, bg="white").image = img  # Keep reference to image
        Label(frame, image=img, bg="white").pack(pady=10)

    # Enter the secret key for decryption
        Label(frame, text="Enter Secret Key (16 characters):", fg="black", font=('Helvetica', 16), bg="white").pack(pady=10)
        secret_key = Entry(frame, font=('Helvetica', 14), show="*")
        secret_key.pack(pady=10)

    # Decrypt button
        Button(frame, text='Decrypt', command=lambda: self.decrypt_data(hidden_data, secret_key.get()), padx=14, pady=8, bd=5, relief="raised", bg="#2980B9", fg="white", font=('Helvetica', 14)).pack(pady=10)

    # Back button
        Button(frame, text='Back', command=self.main_menu, padx=14, pady=8, bd=5, relief="raised", bg="#E74C3C", fg="white", font=('Helvetica', 14)).pack(pady=10)

    def extract_data(self, image):
        binary_data = ""
        pixels = image.load()
        for y in range(image.height):
            for x in range(image.width):
                pixel = list(pixels[x, y])
                for i in range(3):
                    binary_data += str(pixel[i] & 1)

        # Split binary data into bytes
        all_bytes = [binary_data[i: i + 8] for i in range(0, len(binary_data), 8)]

        # Convert from binary to characters
        decoded_data = ""
        for byte in all_bytes:
            decoded_data += chr(int(byte, 2))
            if decoded_data[-5:] == "#####":  # Delimiter indicates end of message
                break

        return decoded_data[:-5] if "#####" in decoded_data else None

    def decrypt_data(self, encrypted_data, key):
        if len(key) != 16:
            messagebox.showerror("Error", "Key must be 16 characters long")
            return

        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            cipher = Cipher(algorithms.AES(key.encode()), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
            original_data = unpadder.update(padded_data) + unpadder.finalize()
            messagebox.showinfo("Decrypted Message", original_data.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

# Run the application
if __name__ == "__main__":
    root = Tk()
    app = Stegno(root)
    root.mainloop()