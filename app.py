import os
from datetime import timedelta
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from helpers import init_db, query, jwt_key
from routes.auth import auth_bp
from routes.vault import vault_bp

load_dotenv()

app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
limiter_db_path = os.path.join(BASE_DIR, "limits.db")

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=f"sqlite:///{limiter_db_path}"  
)

@app.errorhandler(429)
def ratelimit_handler(e):
    return {"error": "Too many requests"}, 429

app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
app.register_blueprint(vault_bp)

if __name__ == "__main__":
    app.run(debug=True)