from flask import Blueprint, request, jsonify, make_response
from datetime import datetime, timezone
from argon2 import PasswordHasher
from flask_jwt_extended import (
    create_access_token, 
    set_access_cookies, 
    unset_jwt_cookies, 
    jwt_required, 
    get_jwt_identity, 
    get_jwt
)
from helpers import query, strict_hex_string, limiter

auth_bp = Blueprint('auth', __name__)
ph = PasswordHasher()

@auth_bp.route("/users", methods=["POST"])
@limiter.limit("5 per minute")
def users():
    user_data = request.get_json()
    username = user_data.get("username")
    user_hash = user_data.get("user_hash")
    user_salt = user_data.get("user_salt")
    wrapped_dek = user_data.get("wrapped_dek")

    if not (username and user_hash and user_salt and wrapped_dek):
        return {"error": "All fields are required to create an account."}, 400
    if len(username) > 255:
            return {"error": "Invalid request payload configuration."}, 400
    try:
        strict_hex_string(user_salt, 32, 32)
        strict_hex_string(user_hash, 64, 64)
        strict_hex_string(wrapped_dek, None, 120)
    except (ValueError, TypeError):
        return {"error": "Invalid request payload configuration."}, 400
    
    pw_hash = ph.hash(user_hash)

    try:
        query("INSERT INTO users(username, hash, salt, wrapped_dek) VALUES (?, ?, ?, ?)", username, pw_hash, user_salt, wrapped_dek)
    except Exception:
        return {"error": "User already exists! Please login instead."}, 400
    
    records = query("SELECT * FROM users WHERE username = ?", username)
    token = create_access_token(identity=str(records[0]["id"]))
    response = jsonify({"status": "success"})
    set_access_cookies(response, token)
    return response, 201

@auth_bp.route("/sessions", methods=["POST"])
@limiter.limit("5 per minute")
def sessions():
    session_data = request.get_json()
    session_username = session_data.get("session_username")
    session_hash = session_data.get("session_hash")

    if not session_username:
        return {"error": "Missing username or password"}, 400
    if session_username and not session_hash:
        if len(session_username) > 255:
            return {"error": "Invalid request payload configuration."}, 400
                 
        user_results = query("SELECT salt, wrapped_dek FROM users WHERE username = ?", session_username)
        if len(user_results) != 1:
            return {"error": "User does not exist! Please register first."}, 404
        
        user = user_results[0]
        return {"status":"success", "salt": user["salt"], "wrapped_dek": user["wrapped_dek"]}, 200                  
    elif session_username and session_hash:

        try:
            strict_hex_string(session_hash, 64, 64)
        except (ValueError, TypeError):
            return {"error": "Invalid request payload configuration."}, 400

        result = query("SELECT id, hash FROM users WHERE username = ?", session_username)
        
        if not result:
            return{"error": "Invalid credentials."}, 401
        
        try:
            ph.verify(result[0]["hash"], session_hash)
            session_token = create_access_token(identity=str(result[0]["id"]))
            session_response = jsonify({"status": "success"})
            set_access_cookies(session_response, session_token)
            return session_response, 200
        except Exception:
            return {"error": "Failed verification."}, 401
    return {"error": "Invalid request."}, 400

@auth_bp.route("/accounts", methods=["GET", "POST", "PATCH"])
@limiter.limit("15 per minute")
@jwt_required()
def accounts():
    user_id = get_jwt_identity()

    if request.method == "GET":
        auth_user = query("SELECT username, salt, wrapped_dek FROM users WHERE id = ?", int(user_id))
        if not auth_user:
            return {"error": "User environment not found."}, 400
        
        result = auth_user[0]
        return{"salt": result["salt"], "wrapped_dek":result["wrapped_dek"]}
    
    elif request.method == "POST":
        data = request.get_json()
        current_hash = data.get("current_hash")
        
        if not current_hash:
            return {"error": "Empty field submitted."}, 400
        try:
            strict_hex_string(current_hash, 64, 64)
        except (ValueError, TypeError):
            return {"error": "Invalid request payload configuration."}, 400

        auth_data = query("SELECT hash FROM users WHERE id = ?", int(user_id))
        if not auth_data:
            return {"error": "User environment not found."}, 404

        try:
            ph.verify(auth_data[0]["hash"], current_hash)
            return {"status": "success"}, 200
        except Exception:
            return {"error": "Incorrect master password. For security, your session has been closed."}, 401        
    else:
        data = request.get_json()
        new_salt = data.get("new_salt")
        new_hash = data.get("new_hash")
        new_wrapped_dek = data.get("new_wrapped_dek")

        if not (new_salt and new_hash and new_wrapped_dek):
            return {"error": "No security-related fields provided"}, 400
        try:
            strict_hex_string(new_salt, 32, 32)
            strict_hex_string(new_hash, 64, 64)
            strict_hex_string(new_wrapped_dek, None, 120)
        except (ValueError, TypeError):
            return {"error": "Invalid request payload configuration."}, 400
        
        updated_hash = ph.hash(new_hash)

        try:
            query("UPDATE users SET hash = ?, salt = ?, wrapped_dek = ? WHERE id = ?", updated_hash, new_salt, new_wrapped_dek, int(user_id))
            return {"status": "success"}, 200
        except Exception:
            return {"error": "An internal error occurred while updating your password."}, 500
             

@auth_bp.route("/sessions", methods=["DELETE"])
@jwt_required()
def logout():
    current_token = get_jwt()
    user_id = get_jwt_identity()
    jti = current_token["jti"]
    ttype = current_token["type"]
    now = datetime.now(timezone.utc)
    
    query("INSERT INTO TOKENBLOCKLIST(user_id, jti, type, created_at) VALUES (?, ?, ?, ?)", int(user_id), jti, ttype, now.isoformat())
    
    res = make_response("", 204)
    res.headers["X-Redirect-To"] = "/"  
    unset_jwt_cookies(res)
    return res