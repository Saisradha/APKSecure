# Deploy APKSecure (backend + OTP) on Render

## 1) Fork or push this repo

## 2) Configure environment variables
Use `.env` locally or set on the platform:
- `APKSECURE_SECRET`: random secret string
- `ALLOW_ORIGIN`: your frontend origin (e.g. https://<your-user>.github.io), or `*` for testing
- **`SMTP_USER`**: Your Gmail email address (REQUIRED for OTP emails)
- **`SMTP_PASS`**: Gmail App Password (REQUIRED - see step 5)
- `SMTP_FROM` (optional, defaults to SMTP_USER)
- `SMTP_HOST` / `SMTP_PORT` (optional, defaults to smtp.gmail.com:587)

**Note**: The app now defaults to Gmail SMTP. OTP emails will only be sent if `SMTP_USER` and `SMTP_PASS` are configured.

## 3) One‑click Render deploy
- Connect repo to Render and select `render.yaml` from this repo.
- Render builds with `pip install -r requirements.txt` and starts Gunicorn.
- Health check: `/health` should return `{ "status": "ok" }`.

## 4) Point frontend to backend
- Host your static site (GitHub Pages or Render Static Site).
- The frontend calls `/auth/*`, `/api/*`, `/events` on the same origin by default.
- If hosting separately, set `ALLOW_ORIGIN` on the backend to your frontend domain.

## 5) Gmail App Password setup (REQUIRED)
1. Go to your Google Account settings
2. Enable **2-Step Verification** (if not already enabled)
3. Navigate to **Security** → **2-Step Verification** → **App passwords**
4. Select **App: Mail** and **Device: Other (Custom name)** → Enter "APKSecure"
5. Click **Generate** and copy the 16-character password
6. Set this as `SMTP_PASS` in your environment variables
7. Set `SMTP_USER` to your Gmail email address

**Important**: Use the App Password, NOT your regular Gmail password!

## 6) Test
- Visit backend URL: `/health`.
- Open your site → enter email → “Send Code” → check your inbox.
