# Deploy APKSecure (backend + OTP) on Render

## 1) Fork or push this repo

## 2) Configure environment variables
Use `.env` locally or set on the platform:
- `APKSECURE_SECRET`: random secret string
- `ALLOW_ORIGIN`: your frontend origin (e.g. https://<your-user>.github.io), or `*` for testing
- `SMTP_HOST` / `SMTP_PORT`
- `SMTP_USER` / `SMTP_PASS` (for Gmail, create an App Password)
- `SMTP_FROM` (optional, defaults to SMTP_USER)

## 3) One‑click Render deploy
- Connect repo to Render and select `render.yaml` from this repo.
- Render builds with `pip install -r requirements.txt` and starts Gunicorn.
- Health check: `/health` should return `{ "status": "ok" }`.

## 4) Point frontend to backend
- Host your static site (GitHub Pages or Render Static Site).
- The frontend calls `/auth/*`, `/api/*`, `/events` on the same origin by default.
- If hosting separately, set `ALLOW_ORIGIN` on the backend to your frontend domain.

## 5) Gmail App Password quick guide
- Turn on 2‑Step Verification → App passwords → App: Mail, Device: Other → Generate.
- Paste the 16‑char password as `SMTP_PASS`.

## 6) Test
- Visit backend URL: `/health`.
- Open your site → enter email → “Send Code” → check your inbox.
