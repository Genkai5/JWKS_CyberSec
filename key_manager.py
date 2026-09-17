import base64
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import rsa


class Key:
    def __init__(self, private_key, kid, expires_at):
        self.private_key = private_key
        self.kid = kid
        self.expires_at = expires_at

    def is_expired(self):
        return datetime.now(timezone.utc) >= self.expires_at


def generate_key(expired=False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


    kid = str(uuid.uuid4()) #gives every key a unique id

    if expired:
        expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    else:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    return Key(private_key, kid, expires_at)

def int_to_base64url(value):
    byte_length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(byte_length, byteorder="big")

    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")


def key_to_jwk(key):
    public_key = key.private_key.public_key()
    public_numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "kid": key.kid,
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e),
    }