import base64
import time
import uuid

import jwt
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)


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

    if "expired" in request.args:
        token = jwt.encode(
            {
                "sub": "user123",
                "iat": now - 3600,
                "exp": now - 60,
            },
            expired_private_key,
            algorithm="RS256",
            headers={"kid": expired_kid},
        )
    else:
        token = jwt.encode(
            {
                "sub": "user123",
                "iat": now,
                "exp": now + 3600,
            },
            valid_private_key,
            algorithm="RS256",
            headers={"kid": valid_kid},
        )

    return token


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    valid_jwk = public_key_to_jwk(valid_private_key, valid_kid)

    return jsonify({
        "keys": [valid_jwk]
    })


if __name__ == "__main__":
    app.run(port=8080)
