import os
import secrets

# Server & Network Configuration
PORT = int(os.getenv("PORT", "8080"))
HOST = os.getenv("HOST", "0.0.0.0")

# Security & Credentials
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "milijon_admin")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(16))

# Domain & Paths
SERVER_DOMAIN = os.getenv("SERVER_DOMAIN", "")  # Auto-detected from Host header if empty
WS_PATH_VLESS = os.getenv("WS_PATH_VLESS", "/milijon-vl")
WS_PATH_TROJAN = os.getenv("WS_PATH_TROJAN", "/milijon-tr")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.getenv("DB_PATH", os.path.join(BASE_DIR, "milijon.db"))
