import hmac
import struct
import hashlib
import base64
import time
import os
from flask import current_app
from flask_mail import Message
from . import mail


def generate_secret():
    return base64.b32encode(os.urandom(10)).decode()


def _hotp(secret, counter, digits=6):
    key = base64.b32decode(secret, casefold=True)
    counter_bytes = struct.pack(">Q", counter)
    h = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def generate_otp(secret, digits=6):
    return _hotp(secret, int(time.time()) // 30, digits)


def verify_otp(secret, code, digits=6, window=1):
    current = int(time.time()) // 30
    for i in range(-window, window + 1):
        expected = _hotp(secret, current + i, digits)
        if hmac.compare_digest(expected, code):
            return True
    return False


def send_otp_email(recipient, otp_code):
    msg = Message(
        "Your Talentos Verification Code",
        recipients=[recipient],
    )
    msg.body = f"Your OTP code is: {otp_code}\nThis code expires in 5 minutes."
    msg.html = f"""
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"></head>
    <body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background:#f4f7fb">
      <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
        <table width="480" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);overflow:hidden">
          <tr><td style="background:linear-gradient(135deg,#2563eb,#7c3aed);padding:24px;text-align:center">
            <h1 style="margin:0;color:#fff;font-size:22px">Talentos</h1>
          </td></tr>
          <tr><td style="padding:32px 28px;text-align:center">
            <p style="color:#6b7280;font-size:14px;margin:0 0 20px">Your verification code</p>
            <div style="background:#f0f5ff;border-radius:10px;padding:20px;margin-bottom:20px;letter-spacing:8px;font-size:36px;font-weight:bold;color:#2563eb;font-family:monospace">{otp_code}</div>
            <p style="color:#6b7280;font-size:13px;margin:0">This code expires in <strong style="color:#374151">5 minutes</strong>.</p>
            <p style="color:#9ca3af;font-size:12px;margin:20px 0 0;border-top:1px solid #e5e7eb;padding-top:16px">If you did not request this code, please ignore this email.</p>
          </td></tr>
        </table>
      </td></tr></table>
    </body></html>"""
    mail.send(msg)


def send_reset_email(recipient, token):
    reset_url = f"http://localhost:5000/reset-password?token={token}"
    msg = Message(
        "Talentos — Password Reset",
        recipients=[recipient],
    )
    msg.body = f"Reset your password here: {reset_url}\nThis link expires in 1 hour."
    msg.html = f"""
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"></head>
    <body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background:#f4f7fb">
      <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
        <table width="480" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);overflow:hidden">
          <tr><td style="background:linear-gradient(135deg,#2563eb,#7c3aed);padding:24px;text-align:center">
            <h1 style="margin:0;color:#fff;font-size:22px">Talentos</h1>
          </td></tr>
          <tr><td style="padding:32px 28px;text-align:center">
            <p style="color:#6b7280;font-size:14px;margin:0 0 20px">Reset your password</p>
            <a href="{reset_url}" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:16px;font-weight:bold">Reset Password</a>
            <p style="color:#9ca3af;font-size:12px;margin:20px 0 0;border-top:1px solid #e5e7eb;padding-top:16px">This link expires in 1 hour. If you did not request this, ignore this email.</p>
          </td></tr>
        </table>
      </td></tr></table>
    </body></html>"""
    mail.send(msg)
