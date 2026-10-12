import base64
import sqlite3
import time
import uuid

import jwt
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

DB_NAME = "totally_not_my_privateKeys.db"


def init_db():
    """Create the keys table if it does not exist."""
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)

def generate_key(expiration):
    """Generate an RSA private key and store it in SQLite."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    pem_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem_key, expiration)
        )
        return cursor.lastrowid


def get_key(expired=False):
    """Retrieve a valid or expired RSA key from SQLite."""
    now = int(time.time())

    with sqlite3.connect(DB_NAME) as conn:
        if expired:
            row = conn.execute(
                "SELECT kid, key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                (now,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1",
                (now,)
            ).fetchone()

    if row is None:
        return None

    kid, pem_key = row
    private_key = serialization.load_pem_private_key(
        pem_key,
        password=None
    )

    return kid, private_key


def int_to_base64url(value):
    """Convert an integer to Base64URL format without padding."""
    length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")


def public_key_to_jwk(private_key, kid):
    """Convert an RSA public key into JWK format."""
    public_numbers = private_key.public_key().public_numbers()

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e),
    }


# Create one valid RSA key pair
valid_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
valid_kid = str(uuid.uuid4())

# Create one expired RSA key pair
expired_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
expired_kid = str(uuid.uuid4())


@app.route("/auth", methods=["POST"])
def auth():
    now = int(time.time())
    expired = "expired" in request.args
    result = get_key(expired=expired)

    if result is None:
        return jsonify({"error": "No matching key found"}), 404

    kid, private_key = result


    if "expired" in request.args:
        token = jwt.encode(
            {
                "sub": "user123",
                "iat": now - 3600,
                "exp": now - 60,
            },
            private_key,
            algorithm="RS256",
            headers={"kid": str(kid)},
        )
    else:
        token = jwt.encode(
            {
                "sub": "user123",
                "iat": now,
                "exp": now + 3600,
            },
            private_key,
            algorithm="RS256",
            headers={"kid": str(kid)},
        )

    return token


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    now = int(time.time())

    with sqlite3.connect(DB_NAME) as conn:
        rows = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ?",
            (now,)
        ).fetchall()

    public_keys = []

    for kid, pem_key in rows:
        private_key = serialization.load_pem_private_key(
            pem_key,
            password=None
        )

        public_keys.append(
            public_key_to_jwk(private_key, str(kid))
        )

    return jsonify({"keys": public_keys})


if __name__ == "__main__":
    init_db()

    now = int(time.time())

    with sqlite3.connect(DB_NAME) as conn:
        valid_count = conn.execute(
            "SELECT COUNT(*) FROM keys WHERE exp > ?", (now,)
        ).fetchone()[0]

        expired_count = conn.execute(
            "SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,)
        ).fetchone()[0]

    if valid_count == 0:
        generate_key(now + 3600)

    if expired_count == 0:
        generate_key(now - 3600)

    app.run(port=8080)
