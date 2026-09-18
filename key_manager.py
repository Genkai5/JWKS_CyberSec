import base64
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import rsa


class Key:
    """Initilizes a key with its own kid and expiration """
    def __init__(self, private_key, kid, expires_at):
        self.private_key = private_key
        self.kid = kid
        self.expires_at = expires_at

    """Returns true if the key has expired"""
    def is_expired(self):
        return datetime.now(timezone.utc) >= self.expires_at


def generate_key(expired=False):
    """Generates a key with a kid and expiration time"""
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
    """Converts integer to base64url"""
    byte_length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(byte_length, byteorder="big")

    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")

def key_to_jwk(key):
    """Converts the private key into public JWK"""
    
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