from flask import Flask, render_template, request
import threading
import os

app = Flask(__name__)

# Function to launch the Tkinter Text-in-Image process
def launch_text():
    os.system("python textcipher.py")  # Adjust the script name/path as needed

# Function to launch the Tkinter Text-in-Video process
def launch_text_in_img():
    os.system("python image.py")  # Replace with your actual script

# Function to launch the Tkinter Text-in-Audio process
def launch_text_in_audio():
    os.system("python audio.py")  # Replace with your actual script

# Function to launch the Analysis and Extraction process
def launch_analyze_video():
    os.system("python analysis_extract.py")  # Replace with your actual script

# Root route now renders home.html
@app.route("/")
def home():
    return render_template("home.html")

# Route for index.html
@app.route("/index")
def index():
    return render_template("index.html")
@app.route("/techniques")
def techniques():
    return render_template("techniques.html")


@app.route("/text_in_image", methods=["POST"])
def text_in():
    threading.Thread(target=launch_text).start()  # Run Tkinter in a separate thread
    return "Text-in-Image process started! You can close this tab."

@app.route("/text_in_video", methods=["POST"])
def text_in_img():
    threading.Thread(target=launch_text_in_img).start()
    return "Text-in-Video process started! You can close this tab."

@app.route("/text_in_audio", methods=["POST"])
def text_in_audio():
    threading.Thread(target=launch_text_in_audio).start()
    return "Text-in-Audio process started! You can close this tab."

@app.route("/analyze_extract", methods=["POST"])
def video():
    threading.Thread(target=launch_analyze_video).start()
    return "Analysis and Extraction process started! You can close this tab."

if __name__ == "__main__":
    app.run(debug=True)
