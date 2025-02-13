import tkinter as tk
from tkinter import filedialog, messagebox
import cv2
from PIL import Image, ImageTk
import base64
import os
import webbrowser
from cryptography.fernet import Fernet

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Video Data Encryptor/Decryptor")
        self.root.geometry("1920x1080")  # Set resolution to full screen
        self.root.state("zoomed")  # Make the window fullscreen

        # Style customization
        self.button_style = {"fg": "white", "font": ("Arial", 12, "bold")}
        self.entry_style = {"highlightthickness": 2, "highlightbackground": "#000", "highlightcolor": "#000"}
        
        # Initialize the video as the background
        self.video_path = r"C:\Users\thont\OneDrive\Desktop\stegno\finalbackground.mp4"  # Path to your MP4 file
        if not os.path.exists(self.video_path):
            messagebox.showerror("Error", "Background video file not found!")
            self.video_path = None
            return

        self.cap = cv2.VideoCapture(self.video_path)

        # Create a canvas for the background
        self.canvas = tk.Canvas(self.root, width=1920, height=1080)
        self.canvas.pack(fill="both", expand=True)

        self.background_label = tk.Label(self.canvas)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.update_video_background()  # Start updating the video frames
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)

        self.init_main_screen()

    def update_video_background(self):
        if self.cap is None:
            return
        ret, frame = self.cap.read()
        if ret:
            # Convert the frame from BGR (OpenCV format) to RGB (PIL format)
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frame_resized = cv2.resize(frame_rgb, (1800, 800))  # Resize to a width of 2000 and height of 900

            frame_image = Image.fromarray(frame_resized)
            frame_photo = ImageTk.PhotoImage(frame_image)

            # Update the label with the new frame and move it to the left
            self.background_label.configure(image=frame_photo)
            self.background_label.image = frame_photo  # Keep a reference to avoid garbage collection

            # Adjust the placement of the background_label to the left
            self.background_label.place(x=0, y=0)  # x=0 moves the image to the left side

            # Repeat every 30ms (adjust timing for smoother or slower video playback)
            self.root.after(30, self.update_video_background)
        else:
            # Reset video capture when it finishes
            self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            self.update_video_background()

    def on_exit(self):
        if self.cap:
            self.cap.release()
        self.root.destroy()

    def open_html(self):
            webbrowser.open("http://127.0.0.1:5000/index")  # Adjust the path if necessary

    def init_main_screen(self):
        self.clear_screen()

        # Create the center frame with specified width and height
        self.center_frame = tk.Frame(self.root, width=500, height=400)
        self.center_frame.place(relx=0.7, rely=0.5, anchor="center")
    
        # Prevent the frame from resizing based on its contents
        self.center_frame.pack_propagate(False)

        # Add title label
        tk.Label(self.center_frame, text="Video Steganography", font=("Arial", 24, "bold")).pack(pady=20)

        # Create a frame to hold the "Encrypt" and "Decrypt" buttons side by side
        button_frame = tk.Frame(self.center_frame)
        button_frame.pack(pady=20)

        # Place the "Encrypt" and "Decrypt" buttons side by side using grid
        tk.Button(button_frame, text="Encrypt", command=self.init_encrypt_screen, bg="#4CAF50", 
                **self.button_style, width=15, height=2).grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Decrypt", command=self.init_decrypt_screen, bg="#2196F3", 
                **self.button_style, width=15, height=2).grid(row=0, column=1, padx=10)

        # Place the "Back to Home" button in the middle of the other two buttons
        tk.Button(self.center_frame, text="Back to Home", command=self.open_html, bg="#00008B", 
                **self.button_style, width=30, height=2).pack(pady=10)


    def init_encrypt_screen(self):
        self.clear_screen()  # Clear the main screen
        self.center_frame = tk.Frame(self.root, bg="white")
        self.center_frame.place(relx=0.7, rely=0.5, anchor="center")  
    # Center the frame

        tk.Label(self.center_frame, text="Enter Message:", font=("Arial", 15), bg="white").pack(pady=5)
        self.message_entry = tk.Text(self.center_frame, width=40, height=3, **self.entry_style)
        self.message_entry.pack(pady=5)

        # Label for entering key
        tk.Label(self.center_frame, text="Enter Key (32 characters):", font=("Arial", 15), bg="white").pack(pady=5)

        # Entry widget to enter the key, with password-style input (display as *)
        self.key_entry = tk.Entry(self.center_frame, show="*", width=40, **self.entry_style)
        self.key_entry.pack(pady=25)

        button_frame = tk.Frame(self.center_frame, bg="white")
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Browse Video File", command=self.browse_file, bg="#4CAF50", **self.button_style, height=2, width=20).grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Encrypt and Hide", command=self.encrypt_message, bg="#F44336", **self.button_style, height=2, width=20).grid(row=0, column=1, padx=10)

        tk.Button(self.center_frame, text="Back", command=self.init_main_screen, bg="#2196F3", **self.button_style, height=2, width=20).pack(pady=10)

    def init_decrypt_screen(self):
        self.clear_screen()  # Clear the main screen
        self.center_frame = tk.Frame(self.root, bg="white")
        self.center_frame.place(relx=0.7, rely=0.5, anchor="center")  # Center the frame

        # Label for entering key
        tk.Label(self.center_frame, text="Enter Key (32 characters):", font=("Arial", 15), bg="white").pack(pady=5)

        # Entry widget to enter the key, with password-style input (display as *)
        self.key_entry = tk.Entry(self.center_frame, show="*", width=40, **self.entry_style)
        self.key_entry.pack(pady=25)

        button_frame = tk.Frame(self.center_frame, bg="white")
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Browse Encrypted Video File", command=self.browse_file, bg="#4CAF50", **self.button_style, height=2, width=25).grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Decrypt and Extract", command=self.decrypt_message, bg="#F44336", **self.button_style, height=2, width=20).grid(row=0, column=1, padx=10)

        tk.Button(self.center_frame, text="Back", command=self.init_main_screen, bg="#2196F3", **self.button_style, height=2, width=20).pack(pady=10)


    def clear_screen(self):
        for widget in self.root.winfo_children():
            if not isinstance(widget, tk.Canvas):
                widget.destroy()

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Video Files", "*.mp4 *.avi")])
        if not self.file_path:
            messagebox.showerror("Error", "No file selected!")

    def encrypt_message(self):
        message = self.message_entry.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()  # Fixed the issue
        if not message or not key or not self.file_path:
            messagebox.showerror("Error", "All fields are required!")
            return
        if len(key) != 32:
            messagebox.showerror("Error", "Key must be exactly 32 characters!")
            return

        cipher_suite = Fernet(base64.urlsafe_b64encode(key.encode().ljust(32)))
        encrypted_message = cipher_suite.encrypt(message.encode())

        try:
            with open(self.file_path, "rb") as file:
                video_data = file.read()

            combined_data = video_data + b":::" + encrypted_message

            output_path = os.path.join(os.path.dirname(self.file_path), "encrypted_video.mp4")
            with open(output_path, "wb") as file:
                file.write(combined_data)

            messagebox.showinfo("Success", f"Message encrypted and hidden successfully!\nOutput File: {output_path}\nEncrypted Message: {encrypted_message.decode()}")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")


    def decrypt_message(self):
        key = self.key_entry.get().strip()
        if not key or not self.file_path:
            messagebox.showerror("Error", "All fields are required!")
            return
        if len(key) != 32:
            messagebox.showerror("Error", "Key must be exactly 32 characters!")
            return

        try:
            with open(self.file_path, "rb") as file:
                combined_data = file.read()

            video_data, encrypted_message = combined_data.rsplit(b":::", 1)

            cipher_suite = Fernet(base64.urlsafe_b64encode(key.encode().ljust(32)))
            decrypted_message = cipher_suite.decrypt(encrypted_message).decode()

            messagebox.showinfo("Success", f"Decrypted Message: {decrypted_message}")

            output_path = os.path.join(os.path.dirname(self.file_path), "original_video.mp4")
            with open(output_path, "wb") as file:
                file.write(video_data)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()