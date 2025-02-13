import wave
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from PIL import Image, ImageTk
import cv2
import webbrowser


# AES Encryption
def aes_encrypt(data, key):
    key = key.encode("utf-8")
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    iv = b"1234567890123456"  # Fixed IV (should be random in production)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data


# AES Decryption
def aes_decrypt(encrypted_data, key):
    try:
        key = key.encode("utf-8")
        iv = b"1234567890123456"  # Fixed IV (should match the encrypt IV)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode("utf-8")
    except Exception:
        raise ValueError("Decryption failed. Please check the key.")


# Hide data in audio
def hide_data_in_audio(input_path, message, key):
    encrypted_message = aes_encrypt(message, key)
    encrypted_message_bytes = encrypted_message + b"###"  # Marker for hidden data

    with wave.open(input_path, "rb") as audio:
        params = audio.getparams()
        frames = audio.readframes(audio.getnframes())

    # Embed the encrypted message in the audio's frames
    modified_frames = bytearray(frames)
    for i in range(len(encrypted_message_bytes)):
        modified_frames[i] = encrypted_message_bytes[i]

    # Save to new file
    output_path = "output_with_hidden_data.wav"
    with wave.open(output_path, "wb") as audio_out:
        audio_out.setparams(params)
        audio_out.writeframes(bytes(modified_frames))

    # Convert encrypted message to hexadecimal format
    
    # Display success message with encrypted text
    messagebox.showinfo(
        "Success",
        f"Data successfully hidden!\nOutput file saved as: {output_path}\n\n"
        f"Encrypted Message: {encrypted_message}"
    )

    return output_path, encrypted_message

# Extract data from audio (Decryption)
def extract_data_from_audio(input_path, key):
    try:
        with wave.open(input_path, "rb") as audio:
            frames = audio.readframes(audio.getnframes())

        # Extract the hidden message
        hidden_data = bytearray()
        for i in range(len(frames)):
            hidden_data.append(frames[i])

        # Split hidden data to extract the encrypted message
        encrypted_message_bytes = bytes(hidden_data).split(b"###")[0]
        decrypted_message = aes_decrypt(encrypted_message_bytes, key)
        messagebox.showinfo("Decrypted Message", f"Decrypted message: {decrypted_message}")
        return decrypted_message
    except ValueError as e:
        messagebox.showerror("Error", str(e))
    except Exception as e:
        messagebox.showerror("Error", "An unexpected error occurred during decryption.")


# GUI Application Class
class AudioSteganographyApp:
    def __init__(self, root, video_path):
        self.root = root
        self.root.title("Audio Steganography")
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

        tk.Label(frame, text="Audio Steganography", font=("Arial", 20, "bold"), bg="#f0f0f0").pack(pady=20)

        # Encrypt and Decrypt buttons
        tk.Button(frame, text="Encrypt and Hide", width=20, height=2, bg="#4CAF50", fg="white", font=("Arial", 14),
                  command=self.encrypt_page).pack(pady=10)

        tk.Button(frame, text="Decrypt and Extract", width=20, height=2, bg="#2196F3", fg="white", font=("Arial", 14),
                  command=self.decrypt_page).pack(pady=10)
        def back_to_index():
            webbrowser.open("http://127.0.0.1:5000/index")  # Adjust the path if necessary

        tk.Button(frame, text="Back", width=20, height=2, bg="#F44336", fg="white", font=("Arial", 14),
              command=back_to_index).pack(pady=10)

    def encrypt_page(self):
        self.clear_widgets()

        frame = tk.Frame(self.root, bg="#f0f0f0", bd=2, relief="ridge")
        frame.place(relx=0.7, rely=0.5, anchor="center", width=800, height=600)

        tk.Label(frame, text="Encrypt and Hide Message", font=("Arial", 24, "bold"), bg="#f0f0f0").pack(pady=30)

        tk.Label(frame, text="Browse Audio File:", bg="#f0f0f0", font=("Arial", 14)).pack()
        file_path_entry = tk.Entry(frame, width=50, font=("Arial", 18))
        file_path_entry.pack(pady=10)
        tk.Button(frame, text="Browse", bg="#FFC107", font=("Arial", 14),
                  command=lambda: file_path_entry.insert(0, filedialog.askopenfilename())).pack(pady=10)

        tk.Label(frame, text="Enter Message to Hide:", bg="#f0f0f0", font=("Arial", 14)).pack()
        message_entry = tk.Entry(frame, width=50, font=("Arial", 18))
        message_entry.pack(pady=10)

        tk.Label(frame, text="Enter Key (16 chars):", bg="#f0f0f0", font=("Arial", 14)).pack()
        key_entry = tk.Entry(frame, width=50, font=("Arial", 18), show="*")
        key_entry.pack(pady=10)

        def encrypt_and_hide():
            file_path = file_path_entry.get()
            message = message_entry.get()
            key = key_entry.get()

            if not file_path or not message or not key:
                messagebox.showerror("Error", "All fields are required!")
                return
            if len(key) != 16:
                messagebox.showerror("Error", "Key must be 16 characters long!")
                return

            try:
                hide_data_in_audio(file_path, message, key)
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

        tk.Label(frame, text="Enter Key (16 chars):", bg="#f0f0f0", font=("Arial", 14)).pack()
        key_entry = tk.Entry(frame, width=50, font=("Arial", 14), show="*")
        key_entry.pack(pady=10)

        def decrypt_and_extract():
            file_path = file_path_entry.get()
            key = key_entry.get()

            if not file_path or not key:
                messagebox.showerror("Error", "All fields are required!")
                return
            if len(key) != 16:
                messagebox.showerror("Error", "Key must be 16 characters long!")
                return

            try:
                extract_data_from_audio(file_path, key)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(frame, text="Decrypt and Extract", bg="#2196F3", fg="white", font=("Arial", 16),
                  command=decrypt_and_extract).pack(pady=20)
        tk.Button(frame, text="Back", bg="#F44336", fg="white", font=("Arial", 16), command=self.create_main_page).pack(
            pady=20)


if __name__ == "__main__":
    video_path =r"C:\\Users\\thont\\OneDrive\\Desktop\\stegno\\finalbackground.mp4"
    root = tk.Tk()
    app = AudioSteganographyApp(root, video_path)
    root.mainloop()
