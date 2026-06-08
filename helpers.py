import os
import sqlite3
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
limiter_db_path = os.path.join(BASE_DIR, "limits.db")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=f"sqlite:///{limiter_db_path}"  
)

def strict_hex_string(val: str, min_len: int = None, max_len: int = None) -> str:
    if not isinstance(val, str):
        raise TypeError("Input must be a string")
    if not val:
        raise ValueError("Input string cannot be empty.")
    if not val.isalnum():
        raise ValueError("Invalid characters detected: only hex digits allowed.")
    
    try:
        int(val, 16)
    except ValueError:
        raise ValueError("String contains non-hexadecimal characters.")
    
    if min_len is not None and len(val) < min_len:
        raise ValueError(f"Minimum of {min_len} hex characters not met.")
    
    if max_len is not None and len(val) > max_len:
        raise ValueError(f"Maximum of {max_len} hex characters exceeded.")

    return val
    
# DB config
def get_db_path():
    db_var = os.getenv("DATABASE_URL", "database.db")
    if not os.path.isabs(db_var):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base_dir, db_var)   
    return db_var

# Query shortcut
def query(sql, *args):
    conn = sqlite3.connect(get_db_path())
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute(sql, args)
        if cursor.description: 
            return cursor.fetchall()
        conn.commit()
        return True
    finally:
        conn.close()

def init_db():       
    # Create users table
    query("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          hash TEXT NOT NULL,
          salt TEXT NOT NULL,
          wrapped_dek TEXT NOT NULL        
        );
    """)
    
    # Create credentials table
    query("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            UNIQUE(user_id, website, username),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)

    # Create token blocklist table
    query("""
        CREATE TABLE IF NOT EXISTS TOKENBLOCKLIST (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            jti TEXT NOT NULL,
            type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
