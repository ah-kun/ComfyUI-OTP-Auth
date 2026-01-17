import os
import pyotp
import configparser
import string
import random
import ipaddress
import time
from collections import defaultdict
from aiohttp import web
from server import PromptServer

# ==========================================
# Config Handling
# ==========================================
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.ini')

def load_config():
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
    
    if 'AUTH' not in config:
        config['AUTH'] = {}
    
    auth_config = config['AUTH']
    save_needed = False

    # 1. SECRET_KEY
    if not auth_config.get('SECRET_KEY'):
        print("Auth: Generating new random SECRET_KEY...")
        auth_config['SECRET_KEY'] = pyotp.random_base32()
        save_needed = True
    
    # 2. COOKIE_NAME
    if not auth_config.get('COOKIE_NAME'):
        print("Auth: Generating new random COOKIE_NAME...")
        random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        auth_config['COOKIE_NAME'] = f"ComfyUI_Auth_{random_suffix}"
        save_needed = True

    # 3. New Config Keys Defaults
    if 'IS_SETUP_COMPLETED' not in auth_config:
        auth_config['IS_SETUP_COMPLETED'] = 'False'
        save_needed = True

    if 'SKIP_AUTH_ON_LOCALHOST' not in auth_config:
        auth_config['SKIP_AUTH_ON_LOCALHOST'] = 'False'
        save_needed = True
        
    if 'IP_WHITELIST' not in auth_config:
        auth_config['IP_WHITELIST'] = ''
        save_needed = True

    if save_needed:
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)
    
    return config

def save_setup_complete(allow_localhost):
    config = load_config()
    config['AUTH']['IS_SETUP_COMPLETED'] = 'True'
    config['AUTH']['SKIP_AUTH_ON_LOCALHOST'] = str(allow_localhost)
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)

# Global Config Object
current_config = load_config()
SECRET_KEY = current_config['AUTH']['SECRET_KEY']
COOKIE_NAME = current_config['AUTH']['COOKIE_NAME']

# ==========================================
# Security / Rate Limiting
# ==========================================
# Simple in-memory rate limiter per IP
# (Not persistent across restarts, but sufficient for runtime brute-force protection)
LOGIN_ATTEMPTS = defaultdict(list)
MAX_ATTEMPTS = 5         # Max failed attempts
WINDOW_SECONDS = 600     # 10 minutes

def check_rate_limit(ip):
    now = time.time()
    attempts = LOGIN_ATTEMPTS[ip]
    
    # Clean up old attempts
    attempts = [t for t in attempts if now - t < WINDOW_SECONDS]
    LOGIN_ATTEMPTS[ip] = attempts
    
    if len(attempts) >= MAX_ATTEMPTS:
        return False # Locked
    return True

def register_failed_attempt(ip):
    LOGIN_ATTEMPTS[ip].append(time.time())

# ==========================================
# HTML Templates
# ==========================================

SETUP_HTML = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ComfyUI Auth Setup</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <style>
        body {{ font-family: sans-serif; background: #1e1e1e; color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
        .box {{ background: #2c2c2c; padding: 2rem; border-radius: 10px; max-width: 400px; width: 100%; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }}
        h2 {{ margin-top: 0; color: #4dabf7; }}
        .step {{ margin: 20px 0; border-top: 1px solid #444; padding-top: 20px; }}
        #qrcode {{ display: flex; justify-content: center; margin: 20px 0; background: #fff; padding: 10px; border-radius: 5px; }}
        input[type="text"] {{ font-size: 1.5rem; padding: 10px; width: 150px; text-align: center; margin: 10px 0; border-radius: 5px; border: none; }}
        label {{ cursor: pointer; display: block; margin: 15px 0; font-size: 0.9rem; color: #ccc; }}
        button {{ font-size: 1.1rem; padding: 12px 30px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; width: 100%; }}
        button:hover {{ background: #0056b3; }}
        .error {{ color: #ff6b6b; margin-top: 10px; min-height: 1.2em; }}
        .secret-text {{ font-family: monospace; background: #333; padding: 5px; border-radius: 3px; font-size: 0.9em; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="box">
        <h2>🛡️ Initial Setup</h2>
        
        <div class="step">
            <p>1. Scan this QR code with Google Authenticator:</p>
            <div id="qrcode"></div>
            <p>Or manually enter key:</p>
            <div class="secret-text">{SECRET_KEY}</div>
        </div>

        <div class="step">
            <p>2. Configuration</p>
            <label>
                <input type="checkbox" id="allow_local"> Allow Localhost (127.0.0.1) without Auth
            </label>
        </div>

        <div class="step">
            <p>3. Verify & Complete</p>
            <input type="text" id="otp" placeholder="123456" maxlength="6" inputmode="numeric">
            <div id="msg" class="error"></div>
            <button onclick="finishSetup()">Complete Setup</button>
        </div>
    </div>
    <script>
        // Generate QR Code
        const secret = "{SECRET_KEY}";
        const label = "ComfyUI-User-Auth";
        const otpauth = `otpauth://totp/${{label}}?secret=${{secret}}&issuer=ComfyUI`;
        new QRCode(document.getElementById("qrcode"), {{
            text: otpauth,
            width: 128,
            height: 128
        }});

        async function finishSetup() {{
            const code = document.getElementById('otp').value;
            const allowLocal = document.getElementById('allow_local').checked;
            const msg = document.getElementById('msg');
            msg.innerText = "Verifying...";
            
            try {{
                const res = await fetch('/custom_auth/setup_complete', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{code: code, allow_localhost: allowLocal}})
                }});
                
                if (res.ok) {{
                    alert("Setup Complete! Reloading...");
                    location.reload();
                }} else {{
                    const data = await res.text();
                    msg.innerText = "Error: " + data;
                }}
            }} catch (e) {{
                msg.innerText = "Connection Error";
            }}
        }}
    </script>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ComfyUI Login</title>
    <style>
        body { font-family: sans-serif; background: #1e1e1e; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .box { background: #2c2c2c; padding: 2rem; border-radius: 10px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        input { font-size: 1.5rem; padding: 10px; width: 150px; text-align: center; margin-bottom: 20px; border-radius: 5px; border: none; }
        button { font-size: 1.2rem; padding: 10px 30px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { color: #ff6b6b; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>🔒 Security Check</h2>
        <div id="msg" class="error"></div>
        <input type="text" id="otp" placeholder="123456" maxlength="6" inputmode="numeric">
        <br>
        <button onclick="login()">Login</button>
    </div>
    <script>
        async function login() {
            const code = document.getElementById('otp').value;
            const res = await fetch('/custom_auth/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({code: code})
            });
            if (res.ok) {
                location.reload(); 
            } else {
                const txt = await res.text();
                document.getElementById('msg').innerText = txt || "Invalid Code";
            }
        }
    </script>
</body>
</html>
"""

# ==========================================
# Helper Functions
# ==========================================
def is_ip_whitelisted(request):
    remote_ip = request.remote
    config = load_config()['AUTH']
    
    if config.getboolean('SKIP_AUTH_ON_LOCALHOST'):
        if remote_ip in ['127.0.0.1', '::1', 'localhost']:
            return True
        
    whitelist_str = config.get('IP_WHITELIST', '')
    if not whitelist_str:
        return False
        
    whitelist = [ip.strip() for ip in whitelist_str.split(',') if ip.strip()]
    
    try:
        user_ip = ipaddress.ip_address(remote_ip)
        for entry in whitelist:
            if '/' in entry: # CIDR
                if user_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            else: # Single IP
                if user_ip == ipaddress.ip_address(entry):
                    return True
    except ValueError:
        pass 
    return False

# ==========================================
# Middleware
# ==========================================
@web.middleware
async def auth_middleware(request, handler):
    if request.path.startswith("/custom_auth/"):
        return await handler(request)

    current_conf = load_config()['AUTH']
    is_setup = current_conf.getboolean('IS_SETUP_COMPLETED')

    if not is_setup:
        return web.Response(text=SETUP_HTML, content_type='text/html')

    if is_ip_whitelisted(request):
        return await handler(request)

    auth_cookie = request.cookies.get(COOKIE_NAME)
    if auth_cookie == "authenticated":
        return await handler(request)
    
    return web.Response(text=LOGIN_HTML, content_type='text/html')

# ==========================================
# Route Handlers
# ==========================================
async def login_handler(request):
    data = await request.json()
    code = data.get("code")
    ip = request.remote
    
    # 1. Check Rate Limit
    if not check_rate_limit(ip):
        return web.Response(status=429, text="Too many failed attempts. Try again later.")

    # 2. Verify Code
    totp = pyotp.TOTP(SECRET_KEY)
    if totp.verify(code): 
        # Clear failures on success? Optional. Keeping them prevents brute force over time.
        # But for UX, we could clear. Let's keep it strict for now.
        resp = web.Response(text="OK")
        resp.set_cookie(COOKIE_NAME, "authenticated", httponly=True, max_age=3600*24*30) 
        return resp
    else:
        register_failed_attempt(ip)
        return web.Response(status=401, text="Invalid Code")

async def setup_handler(request):
    data = await request.json()
    code = data.get("code")
    allow_localhost = data.get("allow_localhost", False)

    totp = pyotp.TOTP(SECRET_KEY)
    if totp.verify(code):
        save_setup_complete(allow_localhost)
        resp = web.Response(text="Setup Completed")
        resp.set_cookie(COOKIE_NAME, "authenticated", httponly=True, max_age=3600*24*30)
        return resp
    else:
        return web.Response(status=400, text="Invalid Code. Please scan the QR correctly.")

# ==========================================
# Server Registration
# ==========================================
server = PromptServer.instance
server.app.middlewares.append(auth_middleware)
server.app.router.add_post("/custom_auth/login", login_handler)
server.app.router.add_post("/custom_auth/setup_complete", setup_handler)

NODE_CLASS_MAPPINGS = {}