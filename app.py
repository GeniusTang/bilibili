import io
import json
import os
import base64
import subprocess
import threading
import time
import uuid

import qrcode
import requests
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


def bili_request(url, params=None, cookies=None):
    """Make a request to Bilibili API with proper headers."""
    resp = requests.get(url, params=params, headers=HEADERS, cookies=cookies, timeout=15)
    resp.raise_for_status()
    return resp.json()


def get_cookies_dict():
    """Get cookies from session."""
    return session.get("cookies", {})


def get_download_dir():
    """Get the current download directory from session or default."""
    d = session.get("download_dir", DEFAULT_DOWNLOAD_DIR)
    os.makedirs(d, exist_ok=True)
    return d


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
    session["logged_in"] = True
    session["uid"] = cookies.get("DedeUserID", "")
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
    session["download_dir"] = path
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
    cookie_file = os.path.join(download_dir, f".cookies_{task_id}.txt")
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


def _download_worker(task_id, bvid, cookie_file, download_dir):
    """Run yt-dlp in a subprocess and track progress."""
    task = download_tasks[task_id]
    url = f"https://www.bilibili.com/video/{bvid}"
    venv_python = os.path.join(SCRIPT_DIR, ".venv", "bin", "yt-dlp")

    cmd = [
        venv_python,
        "--cookies", cookie_file,
        "-f", "bestvideo+bestaudio/best",
        "--ffmpeg-location", "/opt/homebrew/bin/ffmpeg",
        "-o", os.path.join(download_dir, "%(title)s.%(ext)s"),
        "--merge-output-format", "mp4",
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

        for line in proc.stdout:
            line = line.strip()
            if "[download]" in line and "%" in line:
                try:
                    pct = line.split("%")[0].split()[-1]
                    task["progress"] = float(pct)
                except (ValueError, IndexError):
                    pass
                # Parse speed: e.g. "1.23MiB/s"
                import re
                speed_match = re.search(r'(\d+\.?\d*\s*[KMG]i?B/s)', line)
                if speed_match:
                    task["speed"] = speed_match.group(1)
                # Parse ETA: e.g. "ETA 01:23" or "00:45"
                eta_match = re.search(r'ETA\s+(\S+)', line)
                if eta_match:
                    task["eta"] = eta_match.group(1)
            if "[Merger]" in line or "[ExtractAudio]" in line:
                task["status"] = "merging"
                task["speed"] = ""
                task["eta"] = ""

        proc.wait()
        if task["status"] == "cancelled":
            pass  # already set
        elif proc.returncode == 0:
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
    app.run(debug=True, port=5000)
