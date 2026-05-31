import os
import sqlite3
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional
import re

class PasswordUpdateRequest(BaseModel):
    # Strict validation for security core
    # Note: Using your updated field names
    hash: Optional[str] = Field(None, min_length=64, max_length=64)
    salt: Optional[str] = Field(None, min_length=32, max_length=32)
    wrapped_dek: Optional[str] = Field(None, min_length=24, max_length=24)
    ciphertext: Optional[str] = Field(None, min_length=72, max_length=120)
    
    # Allow extra fields (website, username, etc.) to pass through
    model_config = ConfigDict(extra='allow')

    # UPDATED: The validator now references the field names defined above
    @field_validator('hash', 'salt', 'wrapped_dek', 'ciphertext')
    @classmethod
    def validate_hex_if_present(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not re.fullmatch(r'[0-9a-fA-F]+', v):
            raise ValueError('Must be a valid hex string')
        return v.lower()

def get_db_path():
    """Dynamically resolves database path to avoid race conditions with load_dotenv()"""
    return os.getenv("DATABASE_URL", "database.db")

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
    # Create users table (FIXED: Added type definition to wrapped_key and cleaned syntax)
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

def jwt_key():
    """Retrieves the JWT secret key safely from the environment."""
    key = os.getenv("JWT_SECRET_KEY")
    if not key:
        raise ValueError("No JWT_SECRET_KEY found in environment. Did you forget your .env file?")
    return key