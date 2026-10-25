
import jwt
import pytest

import app
import key_manager


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Set up a separate database for each test."""
    monkeypatch.setattr(
        key_manager,
        "DB_FILE",
        str(tmp_path / "test_keys.db")
    )

    key_manager.initialize_db()
    key_manager.ensure_keys()

    app.app.config["TESTING"] = True

    with app.app.test_client() as test_client:
        yield test_client


def test_jwks_returns_only_unexpired_keys(client):
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()
    assert len(data["keys"]) >= 1

    # Every key returned by JWKS should be unexpired.
    valid_keys = key_manager.get_valid_keys()
    valid_kids = [str(key.kid) for key in valid_keys]

    for jwk in data["keys"]:
        assert jwk["kid"] in valid_kids
        assert "d" not in jwk


def test_auth_returns_token(client):
    response = client.post("/auth")

    assert response.status_code == 200
    assert "token" in response.get_json()


def test_auth_token_has_correct_kid(client):
    response = client.post("/auth")

    assert response.status_code == 200

    token = response.get_json()["token"]
    header = jwt.get_unverified_header(token)

    normal_key = key_manager.get_key()

    assert normal_key is not None
    assert header["kid"] == str(normal_key.kid)


def test_expired_auth_uses_expired_key(client):
    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.get_json()["token"]
    header = jwt.get_unverified_header(token)

    expired_key = key_manager.get_key(expired=True)

    assert expired_key is not None
    assert header["kid"] == str(expired_key.kid)
