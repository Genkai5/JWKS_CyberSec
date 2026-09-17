import jwt

from app import app, expired_key, normal_key


def test_jwks_returns_only_unexpired_keys():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()

    assert len(data["keys"]) == 1
    assert data["keys"][0]["kid"] == normal_key.kid


def test_auth_returns_token():
    client = app.test_client()

    response = client.post("/auth")

    assert response.status_code == 200

    data = response.get_json()

    assert "token" in data


def test_auth_token_has_correct_kid():
    client = app.test_client()

    response = client.post("/auth")

    token = response.get_json()["token"]

    header = jwt.get_unverified_header(token)

    assert header["kid"] == normal_key.kid


def test_expired_auth_uses_expired_key():
    client = app.test_client()

    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.get_json()["token"]

    header = jwt.get_unverified_header(token)

    assert header["kid"] == expired_key.kid