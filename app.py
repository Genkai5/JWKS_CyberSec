from datetime import datetime, timezone

import jwt
from flask import Flask, jsonify, request

from key_manager import (
    ensure_keys,
    get_key,
    get_valid_keys,
    initialize_db,
    key_to_jwk,
)

app = Flask(__name__) 

#sets up the database and keys
initialize_db()
ensure_keys()

#creates end point
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Return all currently valid public keys as JWKS."""
    keys = get_valid_keys()

    #turns dictionary into JSON
    return jsonify({"keys": [key_to_jwk(key) for key in keys]}) 

@app.route("/auth", methods=["POST"])
def auth():
    """Create and return a JWT signed with an RSA private key."""
    expired = "expired" in request.args
    key = get_key(expired=expired)

    if key is None:
        return jsonify({"error": "No matching key available"}), 500

    now = int(datetime.now(timezone.utc).timestamp())

    token = jwt.encode(
        {
            "sub": "fake-user",
            "iat": now,
            "exp": int(key.expires_at.timestamp()),
        },
        key.private_key,
        algorithm="RS256",
        headers={"kid": str(key.kid)},
    )

    return jsonify({"token": token})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
