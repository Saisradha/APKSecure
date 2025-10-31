from datetime import datetime, timedelta, timezone
import json
import queue
import random
import threading
import time

import os
import smtplib
from email.mime.text import MIMEText

from flask import Flask, Response, jsonify, render_template, request, session
from flask_cors import CORS


# Load .env if available
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

app = Flask(__name__)
app.secret_key = os.environ.get('APKSECURE_SECRET', 'dev-secret-change-me')
allowed_origin = os.environ.get('ALLOW_ORIGIN', '*')
CORS(
    app,
    resources={r"/auth/*": {"origins": allowed_origin}, r"/api/*": {"origins": allowed_origin}, r"/events": {"origins": allowed_origin}},
    supports_credentials=True,
)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _friendly_app_name(package: str) -> str:
    parts = [p for p in package.split('.') if p]
    if not parts:
        return 'Unknown App'
    generic = {'android', 'app', 'mobile', 'apps', 'client', 'official', 'beta'}
    # prefer the last non-generic token; fallback to last
    for token in reversed(parts):
        clean = token.replace('_', ' ').strip()
        if clean.lower() not in generic:
            return clean.replace('-', ' ').title()
    return parts[-1].replace('_', ' ').replace('-', ' ').title()


def _detect_profile(package_name: str) -> str:
    name = package_name.lower()
    if any(k in name for k in ["camera", "photo", "video"]):
        return "media"
    if any(k in name for k in ["chat", "message", "sms"]):
        return "messaging"
    if any(k in name for k in ["bank", "pay", "wallet", "finance"]):
        return "finance"
    if any(k in name for k in ["goodlock", "good_lock", "samsung", "android.systemui", "launcher", "theme"]):
        return "system_personalization"
    return "generic"


def _actions_for(profile: str, score: int) -> list[str]:
    critical = score >= 75
    elevated = 55 <= score < 75
    base_revoke = "Open Settings → Apps → Permissions and revoke Contacts, SMS, Microphone, and Location as applicable."
    items: list[str] = []

    if profile == "finance":
        if critical:
            items = [
                "Uninstall immediately and install only banking apps from your bank’s verified publisher.",
                base_revoke,
                "Change online banking and email passwords, and enable 2FA.",
                "Check recent transactions and contact your bank’s fraud team if anything looks off.",
            ]
        elif elevated:
            items = [
                base_revoke,
                "Disable overlay/draw-over permissions; they can capture sensitive input.",
                "Monitor transactions and app updates for unusual behavior.",
            ]
        else:
            items = [
                "Keep the app updated and review permission requests after each update.",
            ]
    elif profile == "messaging":
        if critical:
            items = [
                "Uninstall the app; it can send/read SMS without notice.",
                base_revoke,
                "Inspect carrier bill for premium SMS charges.",
            ]
        elif elevated:
            items = [
                base_revoke,
                "Disable default SMS handler role unless required.",
            ]
        else:
            items = ["Limit SMS/MMS access to core features only."]
    elif profile == "media":
        if critical:
            items = [
                "Uninstall or deny Microphone/Camera access whenever not in active use.",
                base_revoke,
                "Clear cached media and review connected cloud accounts.",
            ]
        elif elevated:
            items = [
                base_revoke,
                "Restrict background activity and disable auto-upload to unknown clouds.",
            ]
        else:
            items = ["Verify media permissions are requested only during capture or editing."]
    elif profile == "system_personalization":
        if critical:
            items = [
                "Uninstall modules from untrusted sources.",
                base_revoke,
                "Revoke Draw-over-other-apps for modules that don’t need overlays.",
            ]
        elif elevated:
            items = [
                "Audit modules within the suite and remove those requesting sensitive data.",
                base_revoke,
            ]
        else:
            items = ["Keep modules updated; review overlays and accessibility access regularly."]
    else:  # generic
        if critical:
            items = [
                "Uninstall the application and replace it with a trusted alternative.",
                base_revoke,
                "Scan device with Play Protect and a reputable mobile AV.",
            ]
        elif elevated:
            items = [
                base_revoke,
                "Limit background data and remove unused permissions.",
            ]
        else:
            items = ["Review permission prompts carefully; deny non-essential access."]
    return items


def _base_scan_payload(package_name: str) -> dict:
    profile = _detect_profile(package_name)

    # Generic templates that don't reference a specific app type
    critical_permissions = [
        {
            "name": "android.permission.READ_CONTACTS",
            "reason": "Reads the full address book and may expose personal relationships.",
        },
        {
            "name": "android.permission.SEND_SMS",
            "reason": "Can silently send SMS, including premium-rate messages.",
        },
        {
            "name": "android.permission.RECORD_AUDIO",
            "reason": "Microphone access enables ambient audio capture.",
        },
        {
            "name": "android.permission.ACCESS_FINE_LOCATION",
            "reason": "Tracks precise GPS position, enabling movement profiling.",
        },
    ]

    normal_permissions = [
        {
            "name": "android.permission.INTERNET",
            "reason": "Network connectivity for API calls and content delivery.",
        },
        {
            "name": "android.permission.WAKE_LOCK",
            "reason": "Prevents the device from sleeping during active use.",
        },
        {
            "name": "android.permission.VIBRATE",
            "reason": "Haptic feedback for UI interactions.",
        },
    ]

    if profile == "system_personalization":
        # Adjust expectations for system tools like Good Lock
        normal_permissions.append(
            {
                "name": "android.permission.SYSTEM_ALERT_WINDOW",
                "reason": "Draw over other apps to provide UI modules or overlays.",
            }
        )
        # For system tools, demote READ_CONTACTS if not typically needed
        critical_permissions = [p for p in critical_permissions if p["name"] != "android.permission.READ_CONTACTS"]

    threat_flow = [
        {"label": "Device", "icon": "📱", "type": "source"},
        {"label": "Contacts", "icon": "📞", "type": "risk"},
        {"label": "SMS", "icon": "💬", "type": "risk"},
        {"label": "Microphone", "icon": "🎙️", "type": "risk"},
        {"label": "Unknown Server", "icon": "☁️", "type": "sink"},
    ]

    base_score = 82
    risk_level = "Critical"

    return {
        "package": package_name,
        "app_name": _friendly_app_name(package_name) if package_name else "Calculator Plus",
        "risk_score": base_score,
        "risk_score_text": f"Privacy Risk {round(base_score/10, 1)} / 10",
        "risk_level": risk_level,
        "verdict": "Excessive & dangerous permissions detected for core functionality.",
        "analysis_summary": "The requested permissions exceed what is expected for this app’s purpose, indicating potential data collection or misuse.",
        "permissions": {
            "dangerous": critical_permissions,
            "normal": normal_permissions,
        },
        "threat_flow": threat_flow,
        "actions": _actions_for(profile, base_score),
        "generated_at": _now_iso(),
    }


def build_scan_response(package_name: str) -> dict:
    package = package_name or "com.unknown.app"

    if package.lower() in {
        "com.example.calculatorplus",
        "com.example.calculator",
        "com.example.calculatorpro",
    }:
        return _base_scan_payload(package)

    # Generate a pseudo-randomised response for other packages
    seed = sum(ord(char) for char in package)
    random.seed(seed)

    base_payload = _base_scan_payload(package)
    variability = random.randint(-25, 15)
    score = max(15, min(98, base_payload["risk_score"] + variability))

    if score >= 75:
        level = "Critical"
    elif score >= 55:
        level = "Elevated"
    else:
        level = "Guarded"

    base_payload.update(
        {
            "risk_score": score,
            "risk_score_text": f"Privacy Risk {round(score/10, 1)} / 10",
            "risk_level": level,
            "app_name": _friendly_app_name(package),
        }
    )

    for perm in base_payload["permissions"]["dangerous"]:
        if level == "Guarded":
            perm["reason"] = perm["reason"].replace("silently ", "")

    # Human advice based on risk level
    if level == "Guarded":
        advice = "You can use this application. It appears safe based on requested permissions."
    elif level == "Elevated":
        advice = "Use with caution. Review and trim permissions; keep the app updated."
    else:
        advice = "This application is not safe to use. Consider uninstalling and using a trusted alternative."

    base_payload["usage_advice"] = advice
    # Recompute actions based on the final score/profile
    try:
        profile = _detect_profile(package)
        base_payload["actions"] = _actions_for(profile, score)
    except Exception:
        pass
    base_payload["generated_at"] = _now_iso()
    return base_payload


def build_threat_feed(limit: int = 6) -> list:
    packages = [
        "com.chatwave.secure",
        "com.finance.quickpay",
        "com.stream.playhub",
        "com.games.arcadia",
        "com.notes.cloudsync",
        "com.flashlight.ultra",
    ]

    feed = []
    for package in packages[:limit]:
        result = build_scan_response(package)
        feed.append(
            {
                "package": package,
                "risk_level": result["risk_level"],
                "risk_score": result["risk_score"],
                "summary": result["verdict"],
                "generated_at": result["generated_at"],
            }
        )
    return feed

# --- Simple in-process SSE pub/sub for realtime updates ---
_subscribers_lock = threading.Lock()
_subscribers: list[queue.Queue] = []


def _broadcast(event: dict) -> None:
    with _subscribers_lock:
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(event)
            except Exception:
                dead.append(q)
        for q in dead:
            try:
                _subscribers.remove(q)
            except ValueError:
                pass


def _sse_format(data: dict, event: str | None = None) -> str:
    payload = json.dumps(data, ensure_ascii=False)
    prefix = f"event: {event}\n" if event else ""
    return f"{prefix}data: {payload}\n\n"


@app.route('/')
def home():
    return render_template('index.html')


@app.get('/health')
def health():
    return jsonify({"status": "ok", "time": _now_iso()})


@app.get('/api/scan')
def api_scan():
    package_name = request.args.get('package', 'com.example.calculatorplus')
    payload = build_scan_response(package_name)
    # Broadcast to SSE subscribers
    try:
        _broadcast({"type": "scan", "payload": payload})
    except Exception:
        pass
    return jsonify(payload)


@app.get('/api/threats/latest')
def api_threats_latest():
    feed = build_threat_feed()
    return jsonify({"items": feed, "generated_at": _now_iso()})


@app.get('/events')
def sse_events():
    client_queue: queue.Queue = queue.Queue(maxsize=100)
    with _subscribers_lock:
        _subscribers.append(client_queue)

    def gen():
        try:
            # initial hello
            yield _sse_format({"type": "hello", "ts": _now_iso()})
            last_heartbeat = time.time()
            while True:
                try:
                    item = client_queue.get(timeout=5)
                    yield _sse_format(item)
                except queue.Empty:
                    # heartbeat every ~15s
                    if time.time() - last_heartbeat > 15:
                        yield _sse_format({"type": "heartbeat", "ts": _now_iso()})
                        last_heartbeat = time.time()
        finally:
            with _subscribers_lock:
                try:
                    _subscribers.remove(client_queue)
                except ValueError:
                    pass

    return Response(gen(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
        'Connection': 'keep-alive',
    })


# --- OTP Email Auth (simple, in-memory store) ---
_otp_store: dict[str, dict] = {}


def _send_email(to_email: str, subject: str, body: str) -> bool:
    host = os.environ.get('SMTP_HOST')
    port = int(os.environ.get('SMTP_PORT', '587'))
    user = os.environ.get('SMTP_USER')
    pwd = os.environ.get('SMTP_PASS')
    from_addr = os.environ.get('SMTP_FROM', user or 'no-reply@apksecure.local')

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['To'] = to_email

    try:
        if not host or not user or not pwd:
            # Fallback: log OTP to console
            print(f"[OTP] To={to_email} Subject={subject} Body={body}")
            return True
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, pwd)
            server.sendmail(from_addr, [to_email], msg.as_string())
        return True
    except Exception as exc:
        print(f"Failed to send email: {exc}")
        return False


@app.get('/auth/status')
def auth_status():
    user = session.get('user')
    return jsonify({'authenticated': bool(user), 'email': user})


@app.post('/auth/request-otp')
def auth_request_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip()
    if not email or '@' not in email:
        return jsonify({'ok': False, 'error': 'Invalid email'}), 400
    code = f"{random.randint(100000, 999999)}"
    _otp_store[email] = {'code': code, 'exp': datetime.now(timezone.utc) + timedelta(minutes=5)}
    sent = _send_email(email, 'Your APKSecure login code', f'Your one-time code is: {code}\n\nIt expires in 5 minutes.')
    return jsonify({'ok': bool(sent)})


@app.post('/auth/verify')
def auth_verify():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip()
    code = (data.get('code') or '').strip()
    entry = _otp_store.get(email)
    now = datetime.now(timezone.utc)
    if not entry or entry['exp'] < now:
        return jsonify({'ok': False, 'error': 'Code expired'}), 400
    if entry['code'] != code:
        return jsonify({'ok': False, 'error': 'Invalid code'}), 400
    session['user'] = email
    # clear used code
    try:
        del _otp_store[email]
    except Exception:
        pass
    return jsonify({'ok': True})


@app.post('/auth/logout')
def auth_logout():
    session.pop('user', None)
    return jsonify({'ok': True})


if __name__ == '__main__':
    app.run(debug=True)
