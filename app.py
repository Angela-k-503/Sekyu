import os
from datetime import timedelta
from flask import Flask
from flask_jwt_extended import JWTManager
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from helpers import init_db, query
from routes.auth import auth_bp
from routes.vault import vault_bp
from helpers import limiter

load_dotenv()

if not os.getenv("JWT_SECRET_KEY"):
    raise ValueError("CRITICAL ERROR: 'JWT_SECRET_KEY' is missing from the environment variables (.env file).")

app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

init_db()

# JWT Configuration
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = os.getenv("JWT_COOKIE_SECURE", "False").lower() == "true"
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")

jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    row = query("SELECT 1 FROM TOKENBLOCKLIST WHERE jti = ?", jti)
    return len(row) > 0

@app.after_request
def add_security_and_cache_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-eval'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "object-src 'none';"
    )
    if response.mimetype in ['text/css', 'application/javascript', 'image/png', 'image/jpeg']:
        response.headers["Cache-Control"] = "public, max-age=86400"
    else:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

@app.errorhandler(429)
def ratelimit_handler(e):
    return {"error": "Too many requests"}, 429

app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
app.register_blueprint(vault_bp)

if __name__ == "__main__":
    app.run(debug=True)