import configparser
import hashlib
import hmac
import ipaddress
import os
import random
import secrets
import string
import time
from collections import defaultdict

import pyotp
from aiohttp import web
from server import PromptServer


CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.ini")
PLUGIN_VERSION = "1.1.1"


def _write_config(config):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        config.write(f)


def load_config():
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE, encoding="utf-8")

    if "AUTH" not in config:
        config["AUTH"] = {}

    auth_config = config["AUTH"]
    save_needed = False

    defaults = {
        "IS_SETUP_COMPLETED": "False",
        "SKIP_AUTH_ON_LOCALHOST": "False",
        "IP_WHITELIST": "",
        "SESSION_MAX_AGE_DAYS": "30",
        "COOKIE_SECURE": "Auto",
        "COOKIE_SAMESITE": "Strict",
    }

    if not auth_config.get("SECRET_KEY"):
        print("[ComfyUI-OTP-Auth] Generating TOTP secret.")
        auth_config["SECRET_KEY"] = pyotp.random_base32()
        save_needed = True

    if not auth_config.get("COOKIE_NAME"):
        suffix = "".join(random.choices(string.ascii_letters + string.digits, k=8))
        auth_config["COOKIE_NAME"] = f"ComfyUI_Auth_{suffix}"
        save_needed = True

    if not auth_config.get("SESSION_SECRET"):
        print("[ComfyUI-OTP-Auth] Generating session signing secret.")
        auth_config["SESSION_SECRET"] = secrets.token_urlsafe(48)
        save_needed = True

    for key, value in defaults.items():
        if key not in auth_config:
            auth_config[key] = value
            save_needed = True

    if save_needed:
        _write_config(config)

    return config


def save_setup_complete(allow_localhost):
    config = load_config()
    config["AUTH"]["IS_SETUP_COMPLETED"] = "True"
    config["AUTH"]["SKIP_AUTH_ON_LOCALHOST"] = str(bool(allow_localhost))
    _write_config(config)


current_config = load_config()
SECRET_KEY = current_config["AUTH"]["SECRET_KEY"]
COOKIE_NAME = current_config["AUTH"]["COOKIE_NAME"]
SESSION_SECRET = current_config["AUTH"]["SESSION_SECRET"]


LOGIN_ATTEMPTS = defaultdict(list)
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 600


def _client_ip(request):
    return request.remote or "unknown"


def check_rate_limit(ip):
    now = time.time()
    attempts = [t for t in LOGIN_ATTEMPTS[ip] if now - t < WINDOW_SECONDS]
    LOGIN_ATTEMPTS[ip] = attempts
    return len(attempts) < MAX_ATTEMPTS


def register_failed_attempt(ip):
    LOGIN_ATTEMPTS[ip].append(time.time())


def clear_failed_attempts(ip):
    LOGIN_ATTEMPTS.pop(ip, None)


def _session_max_age_seconds():
    auth = load_config()["AUTH"]
    try:
        days = int(auth.get("SESSION_MAX_AGE_DAYS", "30"))
    except ValueError:
        days = 30
    days = min(max(days, 1), 365)
    return days * 24 * 60 * 60


def _make_session_token():
    issued_at = int(time.time())
    nonce = secrets.token_urlsafe(24)
    payload = f"{issued_at}.{nonce}"
    signature = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}.{signature}"


def _verify_session_token(token):
    if not token:
        return False

    try:
        issued_at_text, nonce, supplied_signature = token.split(".", 2)
        issued_at = int(issued_at_text)
    except (TypeError, ValueError):
        return False

    if not nonce or not supplied_signature:
        return False

    now = int(time.time())
    max_age = _session_max_age_seconds()
    if issued_at > now + 60 or issued_at < now - max_age:
        return False

    payload = f"{issued_at}.{nonce}"
    expected_signature = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(supplied_signature, expected_signature)


def _cookie_secure(request):
    mode = load_config()["AUTH"].get("COOKIE_SECURE", "Auto").strip().lower()
    if mode in {"1", "true", "yes", "on"}:
        return True
    if mode in {"0", "false", "no", "off"}:
        return False
    return bool(request.secure)


def _cookie_samesite():
    value = load_config()["AUTH"].get("COOKIE_SAMESITE", "Strict").strip().capitalize()
    return value if value in {"Strict", "Lax", "None"} else "Strict"


def _set_auth_cookie(response, request):
    max_age = _session_max_age_seconds()
    response.set_cookie(
        COOKIE_NAME,
        _make_session_token(),
        max_age=max_age,
        httponly=True,
        secure=_cookie_secure(request),
        samesite=_cookie_samesite(),
        path="/",
    )


def _clear_auth_cookie(response):
    response.del_cookie(COOKIE_NAME, path="/")


def is_ip_whitelisted(request):
    remote_ip = request.remote
    if not remote_ip:
        return False

    auth_config = load_config()["AUTH"]

    if auth_config.getboolean("SKIP_AUTH_ON_LOCALHOST", fallback=False):
        if remote_ip in {"127.0.0.1", "::1"}:
            return True

    whitelist_str = auth_config.get("IP_WHITELIST", "")
    if not whitelist_str:
        return False

    whitelist = [entry.strip() for entry in whitelist_str.split(",") if entry.strip()]

    try:
        user_ip = ipaddress.ip_address(remote_ip)
        for entry in whitelist:
            try:
                if "/" in entry:
                    if user_ip in ipaddress.ip_network(entry, strict=False):
                        return True
                elif user_ip == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                print(f"[ComfyUI-OTP-Auth] Ignoring invalid whitelist entry: {entry}")
    except ValueError:
        return False

    return False


SETUP_HTML = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ComfyUI Auth Setup</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <style>
        body {{ font-family: sans-serif; background: #1e1e1e; color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
        .box {{ background: #2c2c2c; padding: 2rem; border-radius: 10px; max-width: 430px; width: 100%; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }}
        h2 {{ margin-top: 0; color: #4dabf7; }}
        .step {{ margin: 20px 0; border-top: 1px solid #444; padding-top: 20px; }}
        #qrcode {{ display: flex; justify-content: center; margin: 20px 0; background: #fff; padding: 10px; border-radius: 5px; }}
        input[type="text"] {{ font-size: 1.5rem; padding: 10px; width: 150px; text-align: center; margin: 10px 0; border-radius: 5px; border: none; }}
        label {{ cursor: pointer; display: block; margin: 15px 0; font-size: 0.9rem; color: #ccc; }}
        button {{ font-size: 1.1rem; padding: 12px 30px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; width: 100%; }}
        button:hover {{ background: #0056b3; }}
        .error {{ color: #ff6b6b; margin-top: 10px; min-height: 1.2em; }}
        .secret-text {{ font-family: monospace; background: #333; padding: 5px; border-radius: 3px; font-size: 0.9em; word-break: break-all; }}
        .warning {{ color: #ffd43b; font-size: 0.85rem; line-height: 1.4; }}
    </style>
</head>
<body>
    <div class="box">
        <h2>ComfyUI OTP Initial Setup</h2>
        <div class="step">
            <p>1. Scan this QR code with Google Authenticator or another TOTP app.</p>
            <div id="qrcode"></div>
            <p>Manual key:</p>
            <div class="secret-text">{SECRET_KEY}</div>
        </div>
        <div class="step">
            <p>2. Configuration</p>
            <label>
                <input type="checkbox" id="allow_local"> Allow localhost without authentication
            </label>
            <p class="warning">Do not enable this when a same-host reverse proxy or tunnel makes remote requests appear as localhost.</p>
        </div>
        <div class="step">
            <p>3. Verify & Complete</p>
            <input type="text" id="otp" placeholder="123456" maxlength="6" inputmode="numeric" autocomplete="one-time-code">
            <div id="msg" class="error"></div>
            <button onclick="finishSetup()">Complete Setup</button>
        </div>
    </div>
    <script>
        const secret = "{SECRET_KEY}";
        const label = "ComfyUI-User-Auth";
        const otpauth = `otpauth://totp/${{label}}?secret=${{secret}}&issuer=ComfyUI`;
        new QRCode(document.getElementById("qrcode"), {{
            text: otpauth,
            width: 128,
            height: 128
        }});

        async function finishSetup() {{
            const code = document.getElementById("otp").value;
            const allowLocal = document.getElementById("allow_local").checked;
            const msg = document.getElementById("msg");
            msg.innerText = "Verifying...";

            try {{
                const res = await fetch("/custom_auth/setup_complete", {{
                    method: "POST",
                    headers: {{"Content-Type": "application/json"}},
                    body: JSON.stringify({{code: code, allow_localhost: allowLocal}})
                }});

                if (res.ok) {{
                    location.reload();
                }} else {{
                    msg.innerText = await res.text() || "Setup failed";
                }}
            }} catch (e) {{
                msg.innerText = "Connection Error";
            }}
        }}
    </script>
</body>
</html>
"""


LOGIN_HTML = """<!DOCTYPE html>
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
        .error { color: #ff6b6b; margin-bottom: 15px; min-height: 1.2em; }
    </style>
</head>
<body>
    <div class="box">
        <h2>ComfyUI Security Check</h2>
        <div id="msg" class="error"></div>
        <input type="text" id="otp" placeholder="123456" maxlength="6" inputmode="numeric" autocomplete="one-time-code">
        <br>
        <button onclick="login()">Login</button>
    </div>
    <script>
        async function login() {
            const code = document.getElementById("otp").value;
            const res = await fetch("/custom_auth/login", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({code: code})
            });
            if (res.ok) {
                location.reload();
            } else {
                document.getElementById("msg").innerText = await res.text() || "Invalid Code";
            }
        }
    </script>
</body>
</html>
"""


@web.middleware
async def auth_middleware(request, handler):
    if request.path.startswith("/custom_auth/"):
        return await handler(request)

    auth_config = load_config()["AUTH"]
    if not auth_config.getboolean("IS_SETUP_COMPLETED", fallback=False):
        return web.Response(
            text=SETUP_HTML,
            content_type="text/html",
            headers={"Cache-Control": "no-store"},
        )

    if is_ip_whitelisted(request):
        return await handler(request)

    auth_cookie = request.cookies.get(COOKIE_NAME)
    if _verify_session_token(auth_cookie):
        return await handler(request)

    return web.Response(
        text=LOGIN_HTML,
        content_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


async def _read_json(request):
    try:
        return await request.json()
    except Exception:
        return None


@PromptServer.instance.routes.post("/custom_auth/login")
async def login_handler(request):
    ip = _client_ip(request)
    if not check_rate_limit(ip):
        return web.Response(status=429, text="Too many failed attempts. Try again later.")

    data = await _read_json(request)
    if not isinstance(data, dict):
        register_failed_attempt(ip)
        return web.Response(status=400, text="Invalid request")

    code = str(data.get("code", "")).strip()
    if len(code) != 6 or not code.isdigit():
        register_failed_attempt(ip)
        return web.Response(status=401, text="Invalid Code")

    totp = pyotp.TOTP(SECRET_KEY)
    if not totp.verify(code, valid_window=1):
        register_failed_attempt(ip)
        return web.Response(status=401, text="Invalid Code")

    clear_failed_attempts(ip)
    response = web.Response(text="OK")
    _set_auth_cookie(response, request)
    return response


@PromptServer.instance.routes.post("/custom_auth/setup_complete")
async def setup_handler(request):
    auth_config = load_config()["AUTH"]
    if auth_config.getboolean("IS_SETUP_COMPLETED", fallback=False):
        return web.Response(status=409, text="Setup is already completed.")

    ip = _client_ip(request)
    if not check_rate_limit(ip):
        return web.Response(status=429, text="Too many failed attempts. Try again later.")

    data = await _read_json(request)
    if not isinstance(data, dict):
        register_failed_attempt(ip)
        return web.Response(status=400, text="Invalid request")

    code = str(data.get("code", "")).strip()
    allow_localhost = bool(data.get("allow_localhost", False))

    if len(code) != 6 or not code.isdigit():
        register_failed_attempt(ip)
        return web.Response(status=400, text="Invalid Code")

    totp = pyotp.TOTP(SECRET_KEY)
    if not totp.verify(code, valid_window=1):
        register_failed_attempt(ip)
        return web.Response(status=400, text="Invalid Code. Please scan the QR correctly.")

    clear_failed_attempts(ip)
    save_setup_complete(allow_localhost)
    response = web.Response(text="Setup Completed")
    _set_auth_cookie(response, request)
    return response


@PromptServer.instance.routes.post("/custom_auth/logout")
async def logout_handler(request):
    response = web.Response(text="Logged out")
    _clear_auth_cookie(response)
    return response


PromptServer.instance.app.middlewares.append(auth_middleware)

NODE_CLASS_MAPPINGS = {}
