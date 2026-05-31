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
from helpers import query, PasswordUpdateRequest
from pydantic import ValidationError

auth_bp = Blueprint('auth', __name__)
ph = PasswordHasher()

@auth_bp.route("/users", methods=["POST"])
def users():
    user_data = request.get_json()
    username = user_data.get("username")
    user_hash = user_data.get("user_hash")
    user_salt = user_data.get("user_salt")
    wrapped_dek = user_data.get("wrapped_dek")

    if not username or not user_hash or not user_salt or not wrapped_dek:
        return {"error": "All fields are required to create an account."}, 400
        
    pw_hash = ph.hash(user_hash)

    try:
        query("INSERT INTO users(username, hash, salt, wrapped_kek, wrapped_dek) VALUES (?, ?, ?, ?, ?)", username, pw_hash, user_salt, wrapped_kek, wrapped_dek)
    except Exception:
        return {"error": "User already exists! Please login instead."}, 400
    
    records = query("SELECT * FROM users WHERE username = ?", username)
    token = create_access_token(identity=str(records[0]["id"]))
    response = jsonify({"status": "success", "redirect": "/"})
    set_access_cookies(response, token)
    return response, 201

@auth_bp.route("/sessions", methods=["POST"])
def sessions():
    session_data = request.get_json() or {}
    session_username = session_data.get("session_username")
    session_hash = session_data.get("session_hash")

    if not session_username:
        return {"error": "Missing username or password"}, 400

    # Phase 1: Client requesting salt & wrapped key to calculate master key
    if session_username and not session_hash:         
        user_results = query("SELECT * FROM users WHERE username = ?", session_username)
        if len(user_results) != 1:
            return {"error": "User does not exist! Please register first."}, 404
        user = user_results[0]
        return {"status":"success", "salt": user["salt"], "wrapped_dek": user["wrapped_dek"]}, 200                  
    
    # Phase 2: Client submitting hash calculated from master key
    elif session_username and session_hash:
        results = query("SELECT * FROM users WHERE username = ?", session_username)
        if not results:
            return{"error": "Invalid credentials."}, 401
        try:
            ph.verify(results[0]["hash"], session_hash)
            session_token = create_access_token(identity=str(results[0]["id"]))
            session_response = jsonify({"status": "success"})
            set_access_cookies(session_response, session_token)
            return session_response, 200
        except Exception:
            return {"error": "Failed verification"}, 401
    
    return {"error": "Invalid request."}, 400

@auth_bp.route("/accounts", methods=["GET", "POST", "PATCH"])
@jwt_required()
def accounts():
    user_id = get_jwt_identity()
    raw_data = request.get_json()

    if request.method == "GET":
        auth_user = query("SELECT username, salt, wrapped_dek FROM users WHERE id = ?", int(user_id))
        if not auth_user:
            return {"error": "User environment not found"}, 400
        
        result = auth_user[0]
        return{"salt": result["salt"], "wrapped_dek":result["wrapped_dek"]}
    
    elif request.method == "POST":
        try:
            data = PasswordUpdateRequest(**raw_data)
        except Exception as e:
            return jsonify({"error": str(e)}), 400
        
        provided_data = data.model_dump(exclude_unset=True)
        
        if "hash" not in provided_data:
            return {"error": "Required data not found."}, 400
        
        auth_hash = query("SELECT hash FROM users WHERE id = ?", int(user_id))
        if not auth_hash:
            return {"error": "User environment not found"}, 400
        try:
            ph.verify(auth_hash[0]["hash"], provided_data["hash"])
            return {"status": "success"}, 200
        except Exception:
            return {"error": "Failed verification"}, 401
        
    else:
        try:
            data = PasswordUpdateRequest(**raw_data)
        except Exception as e:
            return jsonify({"error": str(e)}), 400
        
        provided_data = data.model_dump(exclude_unset=True)
        if not provided_data:
            return jsonify({"error": "No data provided for update"}), 400
        
        security_fields = {'hash', 'salt', 'wrapped_dek'}
        if not all(field in provided_data for field in security_fields):
            return jsonify({"error": "No security-related fields provided"}), 400
        
        updated_hash = ph.hash(provided_data["hash"])

        try:
            query("UPDATE users SET hash = ?, salt = ?, wrapped_dek = ? WHERE id = ?", updated_hash, provided_data['salt'], provided_data['wrapped_dek'], int(user_id))
            return {"status": "success"}, 200
        except Exception as e:
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