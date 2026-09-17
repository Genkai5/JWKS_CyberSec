from key_manager import generate_key, key_to_jwk


def test_normal_key_is_not_expired():
    key = generate_key(expired=False)

    assert not key.is_expired()


def test_expired_key_is_expired():
    key = generate_key(expired=True)

    assert key.is_expired()


def test_key_has_unique_kid():
    key1 = generate_key()
    key2 = generate_key()

    assert key1.kid != key2.kid


def test_jwk_contains_required_fields():
    key = generate_key()
    jwk = key_to_jwk(key)

    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == key.kid
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert "n" in jwk
    assert "e" in jwk