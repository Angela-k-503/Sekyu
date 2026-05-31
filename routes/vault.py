from flask import Blueprint, request, render_template, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request, unset_jwt_cookies
from helpers import query, get_db_path
from jwt.exceptions import ExpiredSignatureError
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError
import sqlite3


# No url_prefix needed here since the index sits at root '/'
vault_bp = Blueprint('vault', __name__)

@vault_bp.route("/")
def index():

    authenticated = False

    try:
        verify_jwt_in_request(optional=True)
        user_identity = get_jwt_identity()
        authenticated = user_identity is not None
    except (ExpiredSignatureError, NoAuthorizationError, InvalidHeaderError):
        authenticated = False

    response = make_response(render_template("index.html", authenticated=authenticated))

    # Only clear cookies if something is actually wrong
    if not authenticated:

        unset_jwt_cookies(response)
        # response.set_cookie('access_token_cookie', '', expires=0)
        # response.set_cookie('csrf_access_token', '', expires=0)
    return response

@vault_bp.route("/entries", methods=["POST", "GET"])
@jwt_required()
def entries():
    user_id = get_jwt_identity()

    if request.method == "POST":
        vault_data = request.get_json() or {}
        vault_website = vault_data.get("vault_website")
        vault_username = vault_data.get("vault_username")
        vault_ciphertext = vault_data.get("vault_ciphertext")

        if not vault_website or not vault_username or not vault_ciphertext:
            return {"error": "Required fields missing"}, 400
        
        conn = sqlite3.connect(get_db_path())
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO credentials (user_id, website, username, ciphertext) VALUES (?, ?, ?, ?)", (int(user_id), vault_website, vault_username, vault_ciphertext))
            
            new_id = cursor.lastrowid 
            
            cursor.execute("SELECT id, website, username, ciphertext FROM credentials WHERE id = ?", (new_id,))
            row = cursor.fetchone()
            
            conn.commit()
    
            entry = dict(row)
            return entry, 200    
        except Exception as e:
            conn.rollback()
            return {"error": str(e)}, 500
        finally:
            conn.close()
    else:
        try:
            master_username = query("SELECT username FROM users WHERE id = ?", int(user_id))
            vault_entries = query("SELECT id, website, username, ciphertext FROM credentials WHERE user_id = ?", int(user_id))

            entries = []
            if vault_entries:  # You don't need the extra 'if not' assignment block
                for row in vault_entries:
                    entries.append({ 
                        "id": row["id"],          
                        "website": row["website"],
                        "username": row["username"], 
                        "ciphertext": row["ciphertext"] 
                    })
            return {"masterUsername": master_username[0]["username"], "entries":entries}, 200
        except Exception as e:
            print("exception hit")
            return {"status": "error", "message": str(e)}, 500
    
    
@vault_bp.route("/entries/<int:id>", methods=["PUT", "DELETE"])
@jwt_required()
def entry_operations(id):
    user_id = get_jwt_identity()

    if request.method == "PUT":
        update_data = request.get_json() or {}
        new_username = update_data.get("new_username")
        new_ciphertext = update_data.get("new_ciphertext")
        
        if not new_username and not new_ciphertext:
            return {"error": "You must provide a username or a password to update", "redirect": "/"}, 400

        try:
            if new_username and new_ciphertext:
                query("UPDATE credentials SET username = ?, ciphertext = ? WHERE id = ? AND user_id = ?", new_username, new_ciphertext, id, int(user_id))
            elif new_ciphertext:
                query("UPDATE credentials SET ciphertext = ? WHERE id = ? AND user_id = ?", new_ciphertext, id, int(user_id))
            elif new_username:
                query("UPDATE credentials SET username = ? WHERE id = ? AND user_id = ?", new_username, id, int(user_id))
            return {"status": "success", "redirect": "/"}, 200
        except Exception as e:
            if "UNIQUE constraint failed" in str(e):
                return {"error": "An entry with this username already exists for this site.", "redirect": "/"}, 409
            return {"error": "An internal error occurred while updating your entry.", "redirect": "/"}, 500
    
    if request.method == "DELETE":
        user_id = get_jwt_identity()
        
        entry = query("SELECT 1 FROM credentials WHERE id = ? AND user_id = ?", id, int(user_id))
        if not entry:
            return {"error": "Bad Request: Resource not found or unauthorized access"}, 404
        
        try:
            # Run the operation directly
            query("DELETE FROM credentials WHERE id = ? AND user_id = ?", id, int(user_id))
            res = make_response("", 204)               
            return res
        except Exception as e:
            return {"error": "An internal error occurred while deleting your entry."}, 500