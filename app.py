import hashlib
import io
import json
import os
import base64
import re as _re
import subprocess
import tempfile
import threading
import time
import uuid
from functools import lru_cache
from urllib.parse import urlencode

import qrcode
import requests
from curl_cffi import requests as cffi_requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from flask import Flask, render_template, jsonify, request, session, redirect, url_for

app = Flask(__name__)

# Persist secret key so sessions survive server restarts
_secret_key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret_key")
if os.path.exists(_secret_key_file):
    with open(_secret_key_file, "rb") as f:
        app.secret_key = f.read()
else:
    app.secret_key = os.urandom(24)
    with open(_secret_key_file, "wb") as f:
        f.write(app.secret_key)

app.permanent_session_lifetime = __import__("datetime").timedelta(days=30)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DOWNLOAD_DIR = os.path.join(SCRIPT_DIR, "downloads")
os.makedirs(DEFAULT_DOWNLOAD_DIR, exist_ok=True)

# Track download progress: {task_id: {status, title, progress, error, ...}}
download_tasks = {}
download_procs = {}  # {task_id: subprocess.Popen}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": "https://www.bilibili.com",
}


WBI_MIXIN_KEY_ENC_TAB = [
    46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35,
    27, 43, 5, 49, 33, 9, 42, 19, 29, 28, 44, 14, 39, 12, 38, 41,
    13, 37, 48, 7, 16, 24, 55, 40, 61, 26, 17, 0, 1, 60, 51, 30,
    4, 22, 25, 54, 21, 56, 59, 6, 63, 57, 62, 11, 36, 20, 34, 52,
]

# Cache Wbi keys for 10 minutes
_wbi_cache = {"keys": None, "ts": 0}


def _get_wbi_keys(cookies):
    """Fetch img_key and sub_key from Bilibili nav API."""
    now = time.time()
    if _wbi_cache["keys"] and now - _wbi_cache["ts"] < 600:
        return _wbi_cache["keys"]

    try:
        resp = requests.get(
            "https://api.bilibili.com/x/web-interface/nav",
            headers=HEADERS,
            cookies=cookies,
            timeout=15,
        )
        data = resp.json()
        wbi_img = data["data"]["wbi_img"]
        img_key = wbi_img["img_url"].split("/")[-1].split(".")[0]
        sub_key = wbi_img["sub_url"].split("/")[-1].split(".")[0]
    except Exception:
        # Fallback: return empty keys so requests proceed unsigned
        return ("", "")
    _wbi_cache["keys"] = (img_key, sub_key)
    _wbi_cache["ts"] = now
    return img_key, sub_key


def _get_mixin_key(img_key, sub_key):
    raw = img_key + sub_key
    return "".join(raw[i] for i in WBI_MIXIN_KEY_ENC_TAB)[:32]


def _sign_wbi(params, cookies):
    """Sign params with Wbi for Bilibili API anti-bot."""
    img_key, sub_key = _get_wbi_keys(cookies)
    mixin_key = _get_mixin_key(img_key, sub_key)
    params = dict(params or {})
    params["wts"] = int(time.time())
    # Filter out reserved chars from values
    params = {
        k: _re.sub(r"[!'()*]", "", str(v))
        for k, v in sorted(params.items())
    }
    query = urlencode(params)
    params["w_rid"] = hashlib.md5((query + mixin_key).encode()).hexdigest()
    return params


_cffi_session = cffi_requests.Session(impersonate="chrome")
_cffi_session_ready = False
_last_request_time = 0
_REQUEST_INTERVAL = 0.3  # minimum seconds between requests


def _ensure_cffi_session():
    """Initialize the curl_cffi session by visiting bilibili.com for cookies."""
    global _cffi_session_ready
    if _cffi_session_ready:
        return
    try:
        _cffi_session.get("https://www.bilibili.com", headers=HEADERS, timeout=15)
        fp = _cffi_session.get(
            "https://api.bilibili.com/x/frontend/finger/spi",
            headers=HEADERS, timeout=15,
        ).json()
        if fp.get("data"):
            _cffi_session.cookies.set("buvid3", fp["data"]["b_3"], domain=".bilibili.com")
            _cffi_session.cookies.set("buvid4", fp["data"]["b_4"], domain=".bilibili.com")
    except Exception:
        pass
    _cffi_session_ready = True


def bili_request(url, params=None, cookies=None, sign=True):
    """Make a request to Bilibili API with browser-like TLS fingerprint."""
    global _last_request_time

    _ensure_cffi_session()

    if sign and cookies and "api.bilibili.com" in url:
        params = _sign_wbi(params or {}, cookies)

    # Rate limit requests
    now = time.time()
    wait = _REQUEST_INTERVAL - (now - _last_request_time)
    if wait > 0:
        time.sleep(wait)
    _last_request_time = time.time()

    resp = _cffi_session.get(
        url, params=params, headers=HEADERS, cookies=cookies, timeout=15
    )
    if resp.status_code == 412:
        app.logger.warning("412 for %s, retrying with fresh Wbi keys", url)
        _wbi_cache["ts"] = 0
        if sign and cookies:
            params_orig = {k: v for k, v in (params or {}).items() if k not in ("wts", "w_rid")}
            params = _sign_wbi(params_orig, cookies)
            time.sleep(1)
            resp = _cffi_session.get(
                url, params=params, headers=HEADERS, cookies=cookies, timeout=15
            )
    if resp.status_code == 412:
        return {"code": -412, "message": "请求被限制，请稍后再试", "data": None}
    resp.raise_for_status()
    return resp.json()


def get_cookies_dict():
    """Get cookies from session, including fingerprint cookies."""
    cookies = dict(session.get("cookies", {}))
    fp = session.get("fingerprint_cookies", {})
    for k, v in fp.items():
        cookies.setdefault(k, v)
    return cookies


def _init_fingerprint_cookies():
    """Fetch buvid3/buvid4 fingerprint cookies from Bilibili."""
    if session.get("fingerprint_cookies"):
        return
    try:
        resp = _cffi_session.get(
            "https://api.bilibili.com/x/frontend/finger/spi",
            headers=HEADERS,
            timeout=15,
        )
        data = resp.json()
        if data.get("code") == 0 and data.get("data"):
            session["fingerprint_cookies"] = {
                "buvid3": data["data"].get("b_3", ""),
                "buvid4": data["data"].get("b_4", ""),
            }
    except Exception:
        pass


_DOWNLOAD_DIR_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".download_dir")


def get_download_dir():
    """Get the current download directory."""
    if os.path.exists(_DOWNLOAD_DIR_FILE):
        with open(_DOWNLOAD_DIR_FILE, "r") as f:
            d = f.read().strip()
            if d:
                try:
                    os.makedirs(d, exist_ok=True)
                    return d
                except OSError:
                    pass
    os.makedirs(DEFAULT_DOWNLOAD_DIR, exist_ok=True)
    return DEFAULT_DOWNLOAD_DIR


def set_download_dir(path):
    """Save the download directory."""
    with open(_DOWNLOAD_DIR_FILE, "w") as f:
        f.write(path)


# ── Auth routes ──


@app.route("/")
def index():
    if session.get("logged_in"):
        return redirect(url_for("favorites_page"))
    return render_template("login.html")


@app.route("/api/qrcode/generate")
def generate_qrcode():
    """Generate a QR code for Bilibili login."""
    data = bili_request(
        "https://passport.bilibili.com/x/passport-login/web/qrcode/generate"
    )
    if data["code"] != 0:
        return jsonify({"error": "Failed to generate QR code"}), 500

    qr_url = data["data"]["url"]
    qrcode_key = data["data"]["qrcode_key"]

    # Generate QR code image as base64
    qr = qrcode.make(qr_url, box_size=6, border=2)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return jsonify({"qr_image": qr_b64, "qrcode_key": qrcode_key})


@app.route("/api/qrcode/poll")
def poll_qrcode():
    """Poll QR code scan status."""
    qrcode_key = request.args.get("qrcode_key")
    if not qrcode_key:
        return jsonify({"error": "Missing qrcode_key"}), 400

    resp = requests.get(
        "https://passport.bilibili.com/x/passport-login/web/qrcode/poll",
        params={"qrcode_key": qrcode_key},
        headers=HEADERS,
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()

    status_code = data["data"]["code"]
    # 86101 = not scanned, 86090 = scanned waiting confirm, 86038 = expired, 0 = success
    result = {"status": status_code, "message": data["data"].get("message", "")}

    if status_code == 0:
        # Extract cookies from response
        cookies = {}
        for cookie in resp.cookies:
            cookies[cookie.name] = cookie.value
        # Also parse from URL if present
        url = data["data"].get("url", "")
        if url:
            from urllib.parse import urlparse, parse_qs
            parsed = parse_qs(urlparse(url).query)
            for k, v in parsed.items():
                if k in ("DedeUserID", "SESSDATA", "bili_jct", "DedeUserID__ckMd5"):
                    cookies[k] = v[0]

        session["cookies"] = cookies
        session.permanent = True
        session["logged_in"] = True
        session["uid"] = cookies.get("DedeUserID", "")
        _init_fingerprint_cookies()
        result["success"] = True

    return jsonify(result)


@app.route("/api/captcha")
def get_captcha():
    """Get GeeTest captcha parameters from Bilibili."""
    data = bili_request(
        "https://passport.bilibili.com/x/passport-login/captcha",
        params={"source": "main_web"},
    )
    if data["code"] != 0:
        return jsonify({"error": "Failed to get captcha"}), 500

    gt = data["data"]["geetest"]["gt"]
    challenge = data["data"]["geetest"]["challenge"]
    token = data["data"]["token"]
    return jsonify({"gt": gt, "challenge": challenge, "token": token})


@app.route("/api/login/password", methods=["POST"])
def login_password():
    """Login with username/password + captcha verification."""
    body = request.get_json()
    username = body.get("username", "")
    password = body.get("password", "")
    token = body.get("token", "")
    challenge = body.get("challenge", "")
    validate = body.get("validate", "")
    seccode = body.get("seccode", "")

    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400
    if not validate:
        return jsonify({"error": "请完成验证码"}), 400

    # Step 1: Get RSA public key and salt
    key_data = bili_request(
        "https://passport.bilibili.com/x/passport-login/web/key"
    )
    if key_data["code"] != 0:
        return jsonify({"error": "获取加密密钥失败"}), 500

    pub_key_pem = key_data["data"]["key"]
    salt = key_data["data"]["hash"]

    # Step 2: Encrypt password with RSA
    rsa_key = RSA.import_key(pub_key_pem)
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt((salt + password).encode("utf-8"))
    encrypted_password = base64.b64encode(encrypted).decode()

    # Step 3: Submit login using a Session to track cookies across redirects
    s = requests.Session()
    s.headers.update(HEADERS)

    login_resp = s.post(
        "https://passport.bilibili.com/x/passport-login/web/login",
        data={
            "username": username,
            "password": encrypted_password,
            "token": token,
            "challenge": challenge,
            "validate": validate,
            "seccode": seccode,
            "go_url": "https://www.bilibili.com",
            "source": "main_web",
        },
        timeout=15,
    )
    login_resp.raise_for_status()
    result = login_resp.json()

    if result["code"] != 0:
        return jsonify({"error": result.get("message", "登录失败")}), 400

    login_data = result.get("data", {})
    login_status = login_data.get("status", 0)

    # status=2: risk verification required — need SMS code
    if login_status == 2:
        tmp_token = login_data.get("tmp_token", "")
        session["tmp_token"] = tmp_token
        # Store the requests session cookies for later
        session["tmp_cookies"] = {c.name: c.value for c in s.cookies}
        return jsonify({
            "need_verify": True,
            "tmp_token": tmp_token,
            "message": login_data.get("message", "需要手机验证"),
        })

    return _finish_password_login(s, login_data)


def _finish_password_login(s, login_data):
    """Extract cookies after successful password login and save to session."""
    redirect_url = login_data.get("redirect_url", "")
    if redirect_url:
        try:
            s.get(redirect_url, timeout=15)
        except Exception:
            pass

    cookies = {}
    for cookie in s.cookies:
        cookies[cookie.name] = cookie.value

    if redirect_url:
        from urllib.parse import urlparse, parse_qs
        parsed = parse_qs(urlparse(redirect_url).query)
        for k, v in parsed.items():
            if k in ("DedeUserID", "SESSDATA", "bili_jct", "DedeUserID__ckMd5"):
                cookies.setdefault(k, v[0])

    if not cookies.get("DedeUserID"):
        app.logger.warning(
            "Password login: no DedeUserID. cookies=%s, data=%s",
            list(cookies.keys()), login_data,
        )
        return jsonify({"error": "登录成功但未获取到凭证，请尝试二维码登录"}), 400

    session["cookies"] = cookies
    session.permanent = True
    session["logged_in"] = True
    session["uid"] = cookies.get("DedeUserID", "")
    _init_fingerprint_cookies()
    session.pop("tmp_token", None)
    session.pop("tmp_cookies", None)

    return jsonify({"success": True})


@app.route("/api/login/sms/send", methods=["POST"])
def send_risk_sms():
    """Send SMS verification code for risk verification."""
    tmp_token = session.get("tmp_token")
    if not tmp_token:
        return jsonify({"error": "验证会话已过期，请重新登录"}), 400

    resp = requests.post(
        "https://passport.bilibili.com/x/safecenter/common/sms/send",
        data={"sms_type": "loginTelCheck", "tmp_code": tmp_token},
        headers=HEADERS,
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()

    if data["code"] != 0:
        return jsonify({"error": data.get("message", "发送验证码失败")}), 400

    # Save captcha_key for verification
    captcha_key = data.get("data", {}).get("captcha_key", "")
    session["sms_captcha_key"] = captcha_key

    return jsonify({"success": True})


@app.route("/api/login/sms/verify", methods=["POST"])
def verify_risk_sms():
    """Verify SMS code and exchange for login cookies."""
    body = request.get_json()
    code = body.get("code", "")
    tmp_token = session.get("tmp_token")
    captcha_key = session.get("sms_captcha_key", "")

    if not tmp_token:
        return jsonify({"error": "验证会话已过期，请重新登录"}), 400
    if not code:
        return jsonify({"error": "请输入验证码"}), 400

    s = requests.Session()
    s.headers.update(HEADERS)
    # Restore cookies from password login step
    for name, value in session.get("tmp_cookies", {}).items():
        s.cookies.set(name, value)

    resp = s.post(
        "https://passport.bilibili.com/x/passport-login/web/exchange_cookie",
        data={"tmp_code": tmp_token, "code": code, "captcha_key": captcha_key},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()

    if data["code"] != 0:
        return jsonify({"error": data.get("message", "验证码错误")}), 400

    return _finish_password_login(s, data.get("data", {}))


@app.route("/api/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ── Favorites routes ──


@app.route("/favorites")
def favorites_page():
    if not session.get("logged_in"):
        return redirect(url_for("index"))
    return render_template("favorites.html", home_dir=os.path.expanduser("~"))


@app.route("/api/favorites/folders")
def get_favorite_folders():
    """Get all favorite folders for the logged-in user."""
    cookies = get_cookies_dict()
    uid = session.get("uid")
    if not uid:
        return jsonify({"error": "Not logged in"}), 401

    data = bili_request(
        "https://api.bilibili.com/x/v3/fav/folder/created/list-all",
        params={"up_mid": uid},
        cookies=cookies,
    )
    if data["code"] != 0:
        return jsonify({"error": data.get("message", "API error")}), 400

    folders = []
    for f in data["data"].get("list", []):
        folders.append({
            "id": f["id"],
            "title": f["title"],
            "media_count": f["media_count"],
        })
    return jsonify({"folders": folders})


@app.route("/api/favorites/videos")
def get_favorite_videos():
    """Get videos in a favorite folder."""
    cookies = get_cookies_dict()
    folder_id = request.args.get("folder_id")
    page = int(request.args.get("page", 1))
    if not folder_id:
        return jsonify({"error": "Missing folder_id"}), 400

    data = bili_request(
        "https://api.bilibili.com/x/v3/fav/resource/list",
        params={
            "media_id": folder_id,
            "pn": page,
            "ps": 20,
            "platform": "web",
        },
        cookies=cookies,
    )
    if data["code"] != 0:
        return jsonify({"error": data.get("message", "API error")}), 400

    info = data["data"]
    videos = []
    for m in info.get("medias") or []:
        videos.append({
            "bvid": m.get("bvid", ""),
            "title": m.get("title", ""),
            "cover": m.get("cover", ""),
            "duration": m.get("duration", 0),
            "upper": m.get("upper", {}).get("name", ""),
            "page_count": m.get("page", 0),
            "attr": m.get("attr", 0),  # 9 = invalid/deleted
            "pubtime": m.get("pubtime", 0),
            "fav_time": m.get("fav_time", 0),
        })

    return jsonify({
        "videos": videos,
        "has_more": info.get("has_more", False),
        "total": info.get("info", {}).get("media_count", 0),
    })


# ── Settings routes ──


@app.route("/api/settings/download_dir", methods=["GET"])
def get_download_dir_setting():
    return jsonify({"download_dir": get_download_dir()})


@app.route("/api/settings/download_dir", methods=["POST"])
def set_download_dir_setting():
    data = request.get_json()
    path = data.get("download_dir", "").strip()
    if not path:
        return jsonify({"error": "路径不能为空"}), 400
    path = os.path.expanduser(path)
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as e:
        return jsonify({"error": f"无法创建目录: {e}"}), 400
    set_download_dir(path)
    return jsonify({"download_dir": path})


@app.route("/api/browse")
def browse_directory():
    """List subdirectories for the folder picker."""
    path = request.args.get("path", "").strip()
    if not path:
        path = os.path.expanduser("~")
    path = os.path.expanduser(path)
    path = os.path.abspath(path)

    if not os.path.isdir(path):
        return jsonify({"error": "目录不存在"}), 400

    dirs = []
    try:
        for entry in sorted(os.scandir(path), key=lambda e: e.name.lower()):
            if entry.is_dir() and not entry.name.startswith("."):
                dirs.append(entry.name)
    except PermissionError:
        return jsonify({"error": "没有权限访问该目录"}), 403

    parent = os.path.dirname(path) if path != "/" else None
    return jsonify({"path": path, "parent": parent, "dirs": dirs})


# ── Video info route ──


@app.route("/api/video/info")
def get_video_info():
    """Get video stream info (resolution, size) from Bilibili."""
    cookies = get_cookies_dict()
    bvid = request.args.get("bvid")
    if not bvid:
        return jsonify({"error": "Missing bvid"}), 400

    # First get cid from video info
    view_data = bili_request(
        "https://api.bilibili.com/x/web-interface/view",
        params={"bvid": bvid},
        cookies=cookies,
    )
    if view_data["code"] != 0:
        return jsonify({"error": view_data.get("message", "API error")}), 400

    cid = view_data["data"]["pages"][0]["cid"]

    # Get stream info with highest quality
    play_data = bili_request(
        "https://api.bilibili.com/x/player/playurl",
        params={
            "bvid": bvid,
            "cid": cid,
            "qn": 127,  # request highest quality
            "fnval": 4048,  # dash format
            "fourk": 1,
        },
        cookies=cookies,
    )
    if play_data["code"] != 0:
        return jsonify({"error": play_data.get("message", "API error")}), 400

    result = {"bvid": bvid, "qualities": []}
    pdata = play_data["data"]

    quality_names = {
        127: "8K", 126: "杜比视界", 125: "HDR",
        120: "4K", 116: "1080P60", 112: "1080P+",
        80: "1080P", 74: "720P60", 64: "720P",
        32: "480P", 16: "360P",
    }

    # Use dash format if available
    dash = pdata.get("dash")
    if dash:
        videos = dash.get("video", [])
        seen_qn = set()
        for v in videos:
            qn = v.get("id", 0)
            if qn in seen_qn:
                continue
            seen_qn.add(qn)
            # Find matching audio
            audios = dash.get("audio", [])
            audio_size = 0
            if audios:
                audio_size = audios[0].get("bandwidth", 0) * pdata.get("timelength", 0) / 8000

            video_size = v.get("bandwidth", 0) * pdata.get("timelength", 0) / 8000
            total_size = video_size + audio_size

            result["qualities"].append({
                "qn": qn,
                "label": quality_names.get(qn, f"{qn}"),
                "width": v.get("width", 0),
                "height": v.get("height", 0),
                "size_bytes": int(total_size),
            })
    else:
        # Fallback: use accept_quality list
        for qn in pdata.get("accept_quality", []):
            result["qualities"].append({
                "qn": qn,
                "label": quality_names.get(qn, f"{qn}"),
                "width": 0,
                "height": 0,
                "size_bytes": 0,
            })

    # Sort by quality descending
    result["qualities"].sort(key=lambda x: x["qn"], reverse=True)
    return jsonify(result)


# ── Download routes ──


@app.route("/api/download", methods=["POST"])
def start_download():
    """Start downloading a video using yt-dlp."""
    data = request.get_json()
    bvid = data.get("bvid")
    title = data.get("title", bvid)
    if not bvid:
        return jsonify({"error": "Missing bvid"}), 400

    download_dir = get_download_dir()
    task_id = str(uuid.uuid4())[:8]
    download_tasks[task_id] = {
        "status": "starting",
        "title": title,
        "progress": 0,
        "speed": "",
        "eta": "",
        "error": None,
        "bvid": bvid,
    }

    # Save cookies to a temp file for yt-dlp
    cookies = get_cookies_dict()
    cookie_file = os.path.join(tempfile.gettempdir(), f".cookies_{task_id}.txt")
    _write_cookie_file(cookie_file, cookies)

    thread = threading.Thread(
        target=_download_worker,
        args=(task_id, bvid, cookie_file, download_dir),
        daemon=True,
    )
    thread.start()
    return jsonify({"task_id": task_id})


def _write_cookie_file(path, cookies):
    """Write cookies in Netscape format for yt-dlp."""
    with open(path, "w") as f:
        f.write("# Netscape HTTP Cookie File\n")
        for name, value in cookies.items():
            f.write(f".bilibili.com\tTRUE\t/\tFALSE\t0\t{name}\t{value}\n")


def _embed_video_thumbnail(mp4_path):
    """Extract a frame from the video and embed it as cover art thumbnail.

    Uses mutagen to write a 'covr' atom (works on both macOS and Windows).
    Falls back to ffmpeg attached_pic if mutagen is unavailable.
    """
    try:
        thumb_path = mp4_path + ".thumb.jpg"
        # Extract a frame at 5 seconds from the video itself
        subprocess.run(
            ["/opt/homebrew/bin/ffmpeg", "-y", "-i", mp4_path,
             "-ss", "5", "-vframes", "1", "-q:v", "2", thumb_path],
            capture_output=True, timeout=30,
        )
        if not os.path.exists(thumb_path):
            return

        embedded = False
        # Preferred: mutagen writes covr atom (Windows + macOS compatible)
        try:
            from mutagen.mp4 import MP4, MP4Cover
            video = MP4(mp4_path)
            with open(thumb_path, "rb") as f:
                thumb_data = f.read()
            video["covr"] = [MP4Cover(thumb_data, imageformat=MP4Cover.FORMAT_JPEG)]
            video.save()
            embedded = True
        except Exception:
            pass

        # Fallback: ffmpeg attached_pic (works on macOS Finder)
        if not embedded:
            tmp_path = mp4_path + ".tmp.mp4"
            subprocess.run(
                ["/opt/homebrew/bin/ffmpeg", "-y",
                 "-i", mp4_path,
                 "-i", thumb_path,
                 "-map", "0", "-map", "1",
                 "-c", "copy",
                 "-disposition:v:1", "attached_pic",
                 "-movflags", "+faststart",
                 tmp_path],
                capture_output=True, timeout=120,
            )
            if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
                os.replace(tmp_path, mp4_path)
            else:
                try: os.remove(tmp_path)
                except OSError: pass

        # Clean up thumbnail file
        try: os.remove(thumb_path)
        except OSError: pass
    except Exception:
        pass  # Thumbnail embedding is best-effort


def _download_worker(task_id, bvid, cookie_file, download_dir):
    """Run yt-dlp in a subprocess and track progress."""
    task = download_tasks[task_id]
    url = f"https://www.bilibili.com/video/{bvid}"
    venv_python = os.path.join(SCRIPT_DIR, ".venv", "bin", "yt-dlp")

    cmd = [
        venv_python,
        "--cookies", cookie_file,
        "--no-playlist",
        "-f", "bestvideo+bestaudio/best",
        "--ffmpeg-location", "/opt/homebrew/bin/ffmpeg",
        "-o", os.path.join(download_dir, "%(title)s.%(ext)s"),
        "--merge-output-format", "mp4",
        "--ppa", "ffmpeg:-movflags +faststart",
        "--newline",
        url,
    ]

    try:
        task["status"] = "downloading"
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        download_procs[task_id] = proc

        import re
        output_file = None
        for line in proc.stdout:
            line = line.strip()
            if "[download]" in line and "%" in line:
                try:
                    pct = line.split("%")[0].split()[-1]
                    task["progress"] = float(pct)
                except (ValueError, IndexError):
                    pass
                # Parse speed: e.g. "1.23MiB/s"
                speed_match = re.search(r'(\d+\.?\d*\s*[KMG]i?B/s)', line)
                if speed_match:
                    task["speed"] = speed_match.group(1)
                # Parse ETA: e.g. "ETA 01:23" or "00:45"
                eta_match = re.search(r'ETA\s+(\S+)', line)
                if eta_match:
                    task["eta"] = eta_match.group(1)
            # Capture output filename from Merger or download destination
            if "[Merger]" in line:
                task["status"] = "merging"
                task["speed"] = ""
                task["eta"] = ""
                m = re.search(r'Merging formats into "(.+?)"', line)
                if m:
                    output_file = m.group(1)
            elif "[ExtractAudio]" in line:
                task["status"] = "merging"
                task["speed"] = ""
                task["eta"] = ""
            # Also capture from [download] Destination: lines
            if "[download] Destination:" in line:
                dest = line.split("[download] Destination:", 1)[1].strip()
                if dest.endswith(".mp4"):
                    output_file = dest

        proc.wait()
        if task["status"] == "cancelled":
            pass  # already set
        elif proc.returncode == 0:
            # Embed a thumbnail extracted from the video itself
            if output_file and os.path.exists(output_file):
                _embed_video_thumbnail(output_file)
            elif not output_file:
                # Fallback: find most recent mp4 in download dir
                import glob as _glob
                mp4s = sorted(_glob.glob(os.path.join(download_dir, "*.mp4")),
                              key=os.path.getmtime, reverse=True)
                if mp4s:
                    _embed_video_thumbnail(mp4s[0])
            task["status"] = "done"
            task["progress"] = 100
            task["speed"] = ""
            task["eta"] = ""
        else:
            task["status"] = "error"
            task["error"] = "Download failed"
    except Exception as e:
        task["status"] = "error"
        task["error"] = str(e)
    finally:
        download_procs.pop(task_id, None)
        # Clean up cookie file
        try:
            os.remove(cookie_file)
        except OSError:
            pass


@app.route("/api/download/status")
def download_status():
    """Get status of all download tasks."""
    return jsonify(download_tasks)


@app.route("/api/download/status/<task_id>")
def download_task_status(task_id):
    """Get status of a specific download task."""
    task = download_tasks.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    return jsonify(task)


@app.route("/api/download/cancel/<task_id>", methods=["POST"])
def cancel_download(task_id):
    """Cancel a running download task."""
    task = download_tasks.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    if task["status"] in ("done", "error", "cancelled"):
        return jsonify({"error": "Task already finished"}), 400

    task["status"] = "cancelled"
    task["speed"] = ""
    task["eta"] = ""
    proc = download_procs.get(task_id)
    if proc:
        try:
            proc.terminate()
        except OSError:
            pass
    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)
