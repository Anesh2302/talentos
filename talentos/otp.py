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
    <h2>Talentos Verification</h2>
    <p style="font-size:24px;letter-spacing:4px;font-weight:bold">{otp_code}</p>
    <p>This code expires in 5 minutes.</p>
    """
    mail.send(msg)
