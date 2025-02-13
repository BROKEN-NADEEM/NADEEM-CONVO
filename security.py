import getpass
import hashlib
import time
import os
import socket

# 🔒 पासवर्ड सेट करें (Default: "1234", इसे बदल सकते हैं)
SECURE_PASSWORD = hashlib.sha256("1234".encode()).hexdigest()
LOG_FILE = "access_logs.txt"
FAILED_ATTEMPTS = 0
LOCKOUT_TIME = 30  # ब्रूट-फोर्स प्रोटेक्शन (सेकंड्स में)

# 🔍 IP & Device Name Check Function
def get_device_info():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    except:
        hostname = "Unknown"
        ip_address = "Unknown"
    return hostname, ip_address

# 🔐 पासवर्ड चेक करने का फ़ंक्शन
def authenticate():
    global FAILED_ATTEMPTS

    while FAILED_ATTEMPTS < 3:
        user_pass = getpass.getpass("🔒 Enter Password: ")
        hashed_pass = hashlib.sha256(user_pass.encode()).hexdigest()

        if hashed_pass == SECURE_PASSWORD:
            print("✅ Access Granted!\n")
            log_access("SUCCESS")
            return True
        else:
            print("⛔ Access Denied! Try again.\n")
            log_access("FAILED")
            FAILED_ATTEMPTS += 1

    print(f"🚫 Too many failed attempts! Try again after {LOCKOUT_TIME} seconds.")
    time.sleep(LOCKOUT_TIME)
    return False

# 📜 लॉग स्टोरेज फ़ंक्शन
def log_access(status):
    hostname, ip_address = get_device_info()
    with open(LOG_FILE, "a") as log:
        log.write(f"{time.ctime()} - Access: {status}, User: {os.getenv('USER')}, Device: {hostname}, IP: {ip_address}\n")

# 🚀 मेन फ़ंक्शन
if __name__ == "__main__":
    if authenticate():
        os.system("python3 convo.py")  # ✅ पासवर्ड सही हो तो चैटबॉट ओपन करें
    else:
        print("❌ Unauthorized Access Detected! Exiting...")
