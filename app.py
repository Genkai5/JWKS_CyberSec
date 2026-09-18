from datetime import datetime, timezone

import jwt
from flask import Flask, jsonify, request

from key_manager import generate_key, key_to_jwk

app = Flask(__name__) 

normal_key = generate_key()
expired_key = generate_key(expired=True)

#creates end point
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Return all currently valid public keys as JWKS."""
    keys = []

    #Checks both keys if expired
    for key in [normal_key, expired_key]:
        if not key.is_expired():
            keys.append(key_to_jwk(key))

    #turns dictionary into JSON
    return jsonify({"keys": keys}) 

@app.route("/auth", methods=["POST"])
def auth():
    """Create and return a JWT signed with an RSA private key."""
    if "expired" in request.args:
        key = expired_key
    else:
        key = normal_key

    token = jwt.encode(
        {
            "sub": "fake-user",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(key.expires_at.timestamp()),
        },
        key.private_key,
        algorithm="RS256",
        #pyts key id in jwt header
        headers={
            "kid": key.kid
        },
    )

    return jsonify({"token": token})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

