import base64
import sqlite3
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DB_FILE = "totally_not_my_privateKeys.db"

class Key:
    """Initilizes a key with its own kid and expiration """
    def __init__(self, private_key, kid: int, expires_at: datetime):
        self.private_key = private_key
        self.kid = kid
        self.expires_at = expires_at

    """Returns true if the key has expired"""
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

"""Creates the SQLite database and keys table"""
def initialize_db() -> None:

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keys 
            (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )

def generate_key(expired:bool = False) -> Key:
    """Generates a key with a kid and expiration time"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    now = datetime.now(timezone.utc)

    if expired:
        expires_at = now - timedelta(hours=1)
    else:
        expires_at = now + timedelta(hours=1)

    pem_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Store the key and expiration. SQLite assigns the kid.
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem_key, int(expires_at.timestamp())),
        )
        kid = cursor.lastrowid

    return Key(private_key, kid, expires_at)

def get_key(expired: bool = False) -> Key | None:
    """Retrieve a valid or expired key from the database."""
    now = int(datetime.now(timezone.utc).timestamp())

    if expired:
        query = (
            "SELECT kid, key, exp FROM keys "
            "WHERE exp <= ? ORDER BY exp DESC LIMIT 1"
        )
    else:
        query = (
            "SELECT kid, key, exp FROM keys "
            "WHERE exp > ? ORDER BY exp DESC LIMIT 1"
        )

    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute(query, (now,)).fetchone()

    if row is None:
        return None

    kid, pem_key, expiration = row

    private_key = serialization.load_pem_private_key(
        pem_key,
        password=None,
    )

    expires_at = datetime.fromtimestamp(expiration, timezone.utc)

    return Key(private_key, kid, expires_at)

def int_to_base64url(value: int) -> str:
    """Converts integer to base64url"""
    byte_length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(byte_length, byteorder="big")

    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")

def key_to_jwk(key: Key) -> dict:
    """Converts the private key into public JWK"""
    
    public_key = key.private_key.public_key()
    public_numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "kid": str(key.kid),
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e),
    }

def ensure_keys() -> None:
    """Ensure the database contains at least one valid and one expired key."""
    now = int(datetime.now(timezone.utc).timestamp())

    with sqlite3.connect(DB_FILE) as conn:
        valid = conn.execute(
            "SELECT 1 FROM keys WHERE exp > ? LIMIT 1",
            (now,)
        ).fetchone()

        expired = conn.execute(
            "SELECT 1 FROM keys WHERE exp <= ? LIMIT 1",
            (now,)
        ).fetchone()

    # Create a valid key if the database doesn't have one.
    if valid is None:
        generate_key()

    # Create an expired key if the database doesn't have one.
    if expired is None:
        generate_key(expired=True)

def get_valid_keys() -> list[Key]:
    """Retrieve all keys that have not expired."""
    now = int(datetime.now(timezone.utc).timestamp())

    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ?",
            (now,)
        ).fetchall()

    keys = []

    for kid, pem_key, expiration in rows:
        private_key = serialization.load_pem_private_key(
            pem_key,
            password=None
        )

        expires_at = datetime.fromtimestamp(
            expiration,
            timezone.utc
        )

        keys.append(Key(private_key, kid, expires_at))

    return keys
