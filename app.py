from datetime import timedelta
from flask import Flask
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv

from helpers import init_db, query, jwt_key
# Import blueprints
from routes.auth import auth_bp
from routes.vault import vault_bp

load_dotenv()

app = Flask(__name__)

# Initialize Database
init_db()

# JWT Configuration
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False  # Set to True in production!
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_SECRET_KEY"] = jwt_key()

jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    row = query("SELECT 1 FROM TOKENBLOCKLIST WHERE jti = ?", jti)
    return len(row) > 0

@app.after_request
def add_cache_headers(response):
    if response.mimetype in ['text/css', 'application/javascript', 'image/png', 'image/jpeg']:
        response.headers["Cache-Control"] = "public, max-age=86400"
    else:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# Register Blueprints cleanly
app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
app.register_blueprint(vault_bp)

if __name__ == "__main__":
    app.run(debug=True)