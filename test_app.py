import time

import jwt

from app import app, valid_kid, expired_kid


def test_auth_returns_valid_jwt():
    client = app.test_client()

    response = client.post("/auth")

    assert response.status_code == 200

    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert header["kid"] == valid_kid
    assert payload["exp"] > int(time.time())


def test_expired_auth_returns_expired_jwt():
    client = app.test_client()

    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert header["kid"] == expired_kid
    assert payload["exp"] < int(time.time())


def test_jwks_contains_valid_key():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()

    assert "keys" in data
    assert len(data["keys"]) == 1
    assert data["keys"][0]["kid"] == valid_kid
    assert data["keys"][0]["kty"] == "RSA"


def test_jwks_does_not_contain_expired_key():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")
    data = response.get_json()

    kids = [key["kid"] for key in data["keys"]]

    assert expired_kid not in kids
