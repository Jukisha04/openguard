from flask import Flask, render_template, redirect, url_for
import threading
from run_core import main as run_detection, stop_detection

app = Flask(__name__)
detection_thread = None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start", methods=["POST"])
def start():
    global detection_thread
    if detection_thread is None or not detection_thread.is_alive():
        detection_thread = threading.Thread(target=run_detection, daemon=True)
        detection_thread.start()
    return redirect(url_for("index"))

@app.route("/stop", methods=["POST"])
def stop():
    stop_detection()  # sets stop_flag=True
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
