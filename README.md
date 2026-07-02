# Talentos — Recruitment & Talent Management Platform

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Anesh2302/talentos)

A Flask-based talent management platform with:
- OTP email verification & TOTP two-factor auth
- Password reset via email
- Account lockout after failed attempts
- Role-based access (admin, candidate)
- Todo management with scheduling & daily email summaries
- Candidate & job management
- Login history tracking
- Backup codes for account recovery
- CSV export for all data
- Security dashboard with blocked IPs & breach monitoring

## Quick Start (Local)

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your Gmail SMTP credentials
python run.py
```

## One-Click Deploy to Render

1. Click the **Deploy to Render** button above
2. Sign in with GitHub (free account)
3. Set environment variables:
   - `MAIL_USERNAME` = `simonpetercys@gmail.com`
   - `MAIL_PASSWORD` = your Gmail app password
4. Click **Apply** — your app goes live in ~2 minutes

## Live URLs (after deploy)

| Page | URL |
|------|-----|
| API | `https://talentos.onrender.com` |
| Dashboard | `https://talentos.onrender.com/admin/dashboard` |
| Security | `https://talentos.onrender.com/admin/security` |

## API Endpoints

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register new user |
| POST | `/auth/verify-email` | Verify email with OTP |
| POST | `/auth/login` | Login (password + OTP or backup code) |
| POST | `/auth/logout` | Logout |
| POST | `/auth/forgot-password` | Request password reset |
| POST | `/auth/reset-password` | Reset password with token |
| POST | `/auth/setup-otp` | Enable 2FA |
| POST | `/auth/disable-otp` | Disable 2FA |
| POST | `/auth/change-email` | Change email address |
| POST | `/auth/generate-backup-codes` | Generate 5 recovery codes |
| GET | `/auth/login-history` | Your login history |
| GET | `/profile` | Your profile |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/dashboard` | Web dashboard |
| GET | `/admin/security` | Security dashboard |
| GET | `/admin/todos` | List / search todos |
| POST | `/admin/todos` | Create todo |
| PUT | `/admin/todos/<id>` | Update todo |
| DELETE | `/admin/todos/<id>` | Delete todo |
| GET | `/admin/todos/export` | Download CSV |
| GET | `/admin/login-history` | All login history |

## Security

- OTP via email for registration & login
- TOTP-based two-factor authentication
- Backup codes (5 one-time codes)
- Account lockout after 5 failed attempts
- Login history with IP & user-agent tracking
- Password hashing with Werkzeug
- IP auto-block via projectpop security monitor
- Daily security summary emails
