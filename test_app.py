import sqlite3
import time

import jwt

from app import app, DB_NAME


def get_db_key_ids(expired=False):
    now = int(time.time())
    operator = "<=" if expired else ">"

    with sqlite3.connect(DB_NAME) as conn:
        rows = conn.execute(
            f"SELECT kid FROM keys WHERE exp {operator} ?",
            (now,)
        ).fetchall()

    return {str(row[0]) for row in rows}


def test_auth_returns_valid_jwt():
    client = app.test_client()
    response = client.post("/auth")

    assert response.status_code == 200

    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(
        token, options={"verify_signature": False}
    )

    assert header["kid"] in get_db_key_ids()
    assert payload["exp"] > int(time.time())


def test_expired_auth_returns_expired_jwt():
    client = app.test_client()
    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(
        token, options={"verify_signature": False}
    )

    assert header["kid"] in get_db_key_ids(expired=True)
    assert payload["exp"] < int(time.time())


def test_jwks_contains_valid_keys():
    client = app.test_client()
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()
    assert "keys" in data

    valid_ids = get_db_key_ids()
    returned_ids = {key["kid"] for key in data["keys"]}

    assert returned_ids == valid_ids

    for key in data["keys"]:
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert "n" in key
        assert "e" in key


def test_jwks_does_not_contain_expired_key():
    client = app.test_client()
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()
    returned_ids = {key["kid"] for key in data["keys"]}

    expired_ids = get_db_key_ids(expired=True)

    assert returned_ids.isdisjoint(expired_ids)


def test_database_initialization_and_key_generation(tmp_path, monkeypatch):
    import app as app_module

    test_db = tmp_path / "test_keys.db"
    monkeypatch.setattr(app_module, "DB_NAME", str(test_db))

    # Create the database and its keys table
    app_module.init_db()

    # Generate and store a valid RSA key
    expiration = int(time.time()) + 3600
    kid = app_module.generate_key(expiration)

    # Verify the key was stored correctly
    with sqlite3.connect(test_db) as conn:
        row = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE kid = ?",
            (kid,)
        ).fetchone()

    assert row is not None
    assert row[0] == kid
    assert row[1].startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    assert row[2] == expiration

    # Verify the stored key can be retrieved
    retrieved = app_module.get_key()
    assert retrieved is not None
    assert retrieved[0] == kid
