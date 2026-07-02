# Talentos — Recruitment & Talent Management Platform

A Flask-based talent management platform with:
- OTP email verification
- TOTP two-factor auth
- Account lockout after failed attempts
- Role-based access (candidate, recruiter, admin)
- Candidate & job management

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your Gmail SMTP credentials
python run.py
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /auth/register | Register new user |
| POST | /auth/verify-email | Verify email with OTP |
| POST | /auth/login | Login with password + OTP |
| GET | /profile | Get current user profile |
| GET | /admin/users | List all users |
| GET | /admin/candidates | List candidates |
| GET | /admin/jobs | List jobs |

## Security Features

- OTP via email for registration & login
- TOTP-based two-factor authentication
- Account lockout after 5 failed attempts
- Rate limiting on auth endpoints
- Password hashing with Werkzeug
