import os
from datetime import datetime
from sqlalchemy import create_engine, text
from cryptography.fernet import Fernet

# ---- MASTER KEY ----
MASTER_KEY = os.environ.get("MASTER_KEY")
if not MASTER_KEY:
    raise RuntimeError("MASTER_KEY not set. Please run: setx MASTER_KEY <your_key> and reopen PowerShell.")
master_fernet = Fernet(MASTER_KEY.encode())

# ---- Native SQLite connection (no ODBC) ----
db_path = r"C:\Users\hp\source\repos\Token\vault.db"
engine = create_engine(
    f"sqlite:///{db_path}",
    echo=False
)

# ---- SCHEMA ----
schema_sql = """
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    encrypted_value BLOB NOT NULL,
    encrypted_key BLOB NOT NULL,
    created_at TEXT NOT NULL,
    purpose TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_name TEXT,
    action TEXT,
    timestamp TEXT
);
"""

def init_db():
    with engine.begin() as cx:
        for stmt in schema_sql.strip().split(";"):
            if stmt.strip():
                cx.execute(text(stmt))

def store_token(name: str, plaintext_value: str, purpose: str = ""):
    # 1. Generate Data Encryption Key (DEK)
    dek = Fernet.generate_key()
    f_data = Fernet(dek)
    ciphertext = f_data.encrypt(plaintext_value.encode())

    # 2. Encrypt DEK with master key
    wrapped_dek = master_fernet.encrypt(dek)
    ts = datetime.utcnow().isoformat()

    with engine.begin() as cx:
        cx.execute(text("""
            INSERT INTO tokens(name, encrypted_value, encrypted_key, created_at, purpose)
            VALUES (:n,:v,:k,:t,:p)
        """), {"n": name, "v": ciphertext, "k": wrapped_dek, "t": ts, "p": purpose})
        cx.execute(text("""
            INSERT INTO audit_log(token_name, action, timestamp)
            VALUES (:n,'CREATE',:t)
        """), {"n": name, "t": ts})
    print(f"[*] Stored token '{name}' securely.")

def retrieve_token(name: str) -> str:
    ts = datetime.utcnow().isoformat()
    with engine.begin() as cx:
        row = cx.execute(text("""
            SELECT encrypted_value, encrypted_key FROM tokens WHERE name=:n
        """), {"n": name}).fetchone()
        if not row:
            raise KeyError(f"Token not found: {name}")
        enc_val, enc_dek = row
        dek = master_fernet.decrypt(enc_dek)
        f_data = Fernet(dek)
        plaintext = f_data.decrypt(enc_val).decode()
        cx.execute(text("""
            INSERT INTO audit_log(token_name, action, timestamp)
            VALUES (:n,'READ',:t)
        """), {"n": name, "t": ts})
        return plaintext

def show_audit():
    with engine.begin() as cx:
        rows = cx.execute(text("""
            SELECT token_name, action, timestamp FROM audit_log ORDER BY id
        """)).fetchall()
        for r in rows:
            print(f"{r.token_name:15} {r.action:6} {r.timestamp}")

if __name__ == "__main__":
    init_db()
    print("[*] Vault ready at:", db_path)

    # Demo
    store_token("api_key", "super-secret-value-123", purpose="Demo API key")
    secret = retrieve_token("api_key")
    print("[*] Retrieved token plaintext:", secret)

    print("\nAudit log:")
    show_audit()
