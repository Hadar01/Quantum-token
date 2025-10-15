# vault_cli.py
import os, sys
from urllib.parse import quote_plus
import subprocess, re

import pyodbc
from sqlalchemy import create_engine, text
from cryptography.fernet import Fernet

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
import pyfiglet
from sqlalchemy.exc import IntegrityError


import tokenGen  # your existing generator (must have if __name__ == "__main__" guard)

console = Console()

# ===== MASTER KEY =====
MASTER_KEY = os.environ.get("MASTER_KEY")
if not MASTER_KEY:
    console.print("[bold red]ERROR:[/bold red] MASTER_KEY not set. Run [yellow]setx MASTER_KEY <your_key>[/yellow] and reopen PowerShell.")
    sys.exit(1)
master_fernet = Fernet(MASTER_KEY.encode())

# ===== LocalDB helpers =====
def _choose_driver():
    # Prefer 18, then 17, then "SQL Server"
    ds = [d.lower() for d in pyodbc.drivers()]
    for name in ("odbc driver 18 for sql server", "odbc driver 17 for sql server", "sql server"):
        if name in ds:
            return [d for d in pyodbc.drivers() if d.lower() == name][0]
    raise RuntimeError("No SQL Server ODBC driver found (install 18 x64).")

def _ensure_localdb_instance():
    try:
        subprocess.check_call(["sqllocaldb", "start", "MSSQLLocalDB"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        subprocess.check_call(["sqllocaldb", "create", "MSSQLLocalDB"])
        subprocess.check_call(["sqllocaldb", "start", "MSSQLLocalDB"])

def _get_localdb_pipe():
    out = subprocess.check_output(["sqllocaldb", "info", "MSSQLLocalDB"], text=True)
    m = re.search(r"Instance pipe name:\s*(\S+)", out)
    return m.group(1) if m else None

def ensure_localdb_database(driver, db_name="TokenVault"):
    cs_master = f"DRIVER={{{driver}}};SERVER=(localdb)\\MSSQLLocalDB;Trusted_Connection=Yes;Encrypt=No;DATABASE=master"
    with pyodbc.connect(cs_master, autocommit=True) as conn:
        conn.cursor().execute(f"IF DB_ID('{db_name}') IS NULL CREATE DATABASE {db_name};")

def build_engine():
    pyodbc.pooling = False  # SQLAlchemy handles pooling
    _ensure_localdb_instance()
    driver = _choose_driver()
    ensure_localdb_database(driver, "TokenVault")

    # Try instance form first
    odbc = (
        f"DRIVER={{{driver}}};"
        r"SERVER=(localdb)\MSSQLLocalDB;"
        r"Trusted_Connection=Yes;Encrypt=No;"
        r"DATABASE=TokenVault"
    )
    url = "mssql+pyodbc:///?odbc_connect=" + quote_plus(odbc)
    engine = create_engine(url, pool_size=5, max_overflow=2, pool_timeout=30, echo=False)
    # Smoke test
    try:
        with engine.connect() as cx:
            cx.execute(text("select 1"))
        return engine, driver, "(localdb)\\MSSQLLocalDB"
    except Exception:
        # Fallback to named pipe (bulletproof)
        pipe = _get_localdb_pipe()
        if not pipe:
            raise
        odbc2 = f"DRIVER={{{driver}}};SERVER=np:{pipe}\\tsql\\query;Trusted_Connection=Yes;Encrypt=No;DATABASE=TokenVault"
        url2 = "mssql+pyodbc:///?odbc_connect=" + quote_plus(odbc2)
        engine2 = create_engine(url2, pool_size=5, max_overflow=2, pool_timeout=30, echo=False)
        with engine2.connect() as cx:
            cx.execute(text("select 1"))
        return engine2, driver, f"np:{pipe}\\tsql\\query"

engine, _driver, _server_display = build_engine()

# ===== Schema (SQL Server) =====
def init_db():
    stmts = [
        """
        IF OBJECT_ID('dbo.tokens','U') IS NULL
        CREATE TABLE dbo.tokens (
          id INT IDENTITY(1,1) PRIMARY KEY,
          name NVARCHAR(255) NOT NULL UNIQUE,
          encrypted_value VARBINARY(MAX) NOT NULL,
          encrypted_key   VARBINARY(MAX) NOT NULL,
          created_at DATETIME2 NOT NULL,
          purpose NVARCHAR(255) NULL
        );
        """,
        """
        IF OBJECT_ID('dbo.audit_log','U') IS NULL
        CREATE TABLE dbo.audit_log (
          id INT IDENTITY(1,1) PRIMARY KEY,
          token_name NVARCHAR(255),
          action NVARCHAR(20),
          timestamp DATETIME2
        );
        """
    ]
    with engine.begin() as cx:
        for s in stmts:
            cx.execute(text(s))

# ===== Vault ops =====
def store_token(name: str, plaintext_value: str, purpose: str = "") -> str:
    """
    Insert a new token. If the name already exists, inform the user and do nothing.
    Returns: "CREATE" on success, "DUPLICATE" if the name exists.
    """
    # Envelope encryption
    dek = Fernet.generate_key()
    ciphertext = Fernet(dek).encrypt(plaintext_value.encode())
    wrapped_dek = master_fernet.encrypt(dek)

    with engine.begin() as cx:
        try:
            cx.execute(text("""
                INSERT INTO dbo.tokens(name, encrypted_value, encrypted_key, created_at, purpose)
                VALUES (:n, :v, :k, SYSUTCDATETIME(), :p)
            """), {"n": name, "v": ciphertext, "k": wrapped_dek, "p": purpose})

            cx.execute(text("""
                INSERT INTO dbo.audit_log(token_name, action, timestamp)
                VALUES (:n, 'CREATE', SYSUTCDATETIME())
            """), {"n": name})

            console.print(f"✅ Token [bold cyan]{name}[/bold cyan] stored.", style="green")
            return "CREATE"

        except IntegrityError as e:
            # SQL Server duplicate key: 2627 (unique constraint) or 2601 (duplicate index)
            msg = str(getattr(e, "orig", e))
            if "2627" in msg or "2601" in msg or "UNIQUE" in msg.upper():
                console.print(f"[yellow]Token name [bold]{name}[/bold] already exists. "
                              f"Please choose a different name.[/yellow]")
                return "DUPLICATE"
            # Not a duplicate — re-raise so caller prints the real error
            raise




def retrieve_token(name: str):
    with engine.begin() as cx:
        row = cx.execute(text("""
          SELECT encrypted_value, encrypted_key FROM dbo.tokens WHERE name=:n
        """), {"n": name}).fetchone()
        if not row:
            console.print(f"[red]Token '{name}' not found.[/red]")
            return
        enc_val, enc_dek = row
        dek = master_fernet.decrypt(enc_dek)
        plaintext = Fernet(dek).decrypt(enc_val).decode()
        cx.execute(text("""
          INSERT INTO dbo.audit_log(token_name, action, timestamp)
          VALUES (:n, 'READ', SYSUTCDATETIME())
        """), {"n": name})
    console.print(f"🔑 Retrieved token: [yellow]{plaintext[:80]}[/yellow]")

def delete_token(name: str):
    with engine.begin() as cx:
        res = cx.execute(text("DELETE FROM dbo.tokens WHERE name=:n"), {"n": name})
        if res.rowcount == 0:
            console.print(f"[red]Token '{name}' not found.[/red]")
            return
        cx.execute(text("""
          INSERT INTO dbo.audit_log(token_name, action, timestamp)
          VALUES (:n, 'DELETE', SYSUTCDATETIME())
        """), {"n": name})
    console.print(f"🗑️  Deleted token [bold]{name}[/bold].", style="green")

def list_tokens():
    with engine.begin() as cx:
        rows = cx.execute(text("""
          SELECT name, created_at, purpose FROM dbo.tokens ORDER BY id
        """)).fetchall()
    if not rows:
        console.print("[dim]No tokens stored.[/dim]")
        return
    table = Table(title="Stored Tokens")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Created At (UTC)", style="magenta")
    table.add_column("Purpose", style="green")
    for r in rows:
        table.add_row(r.name, str(r.created_at), r.purpose or "")
    console.print(table)

def show_audit():
    with engine.begin() as cx:
        rows = cx.execute(text("""
          SELECT token_name, action, timestamp FROM dbo.audit_log ORDER BY id
        """)).fetchall()
    if not rows:
        console.print("[dim]Audit log is empty.[/dim]")
        return
    table = Table(title="Audit Log")
    table.add_column("Token", style="cyan")
    table.add_column("Action", style="yellow")
    table.add_column("Timestamp (UTC)", style="magenta")
    for r in rows:
        table.add_row(r.token_name or "", r.action, str(r.timestamp))
    console.print(table)

# ===== CLI =====
def main():
    init_db()
    banner = pyfiglet.figlet_format("TOKEN VAULT", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print(Panel(f"🔐 Secure Token Vault\nODBC Driver: {_driver}\nServer: {_server_display}\nDB: TokenVault", style="blue"))

    while True:
        console.print("\n[bold yellow]Menu:[/bold yellow]")
        console.print("[cyan]1[/cyan]. Generate + Store Token")
        console.print("[cyan]2[/cyan]. Retrieve Token")
        console.print("[cyan]3[/cyan]. List All Tokens")
        console.print("[cyan]4[/cyan]. Show Audit Log")
        console.print("[cyan]5[/cyan]. Delete Token")
        console.print("[cyan]6[/cyan]. Exit")

        choice = Prompt.ask("Choose an option", choices=[str(i) for i in range(1,7)])

        if choice == "1":
            rnd = tokenGen.generate_random_decimal(16)
            token_val = tokenGen.generate_secure_token(rnd, token_size=16)
            name = Prompt.ask("Enter token name")
            purpose = Prompt.ask("Enter purpose/description", default="")
            try:
                store_token(name, token_val, purpose)
            except Exception as e:
                console.print(f"[red]Error storing token: {e}[/red]")

        elif choice == "2":
            name = Prompt.ask("Enter token name to retrieve")
            try:
                retrieve_token(name)
            except Exception as e:
                console.print(f"[red]Error retrieving token: {e}[/red]")

        elif choice == "3":
            list_tokens()

        elif choice == "4":
            show_audit()

        elif choice == "5":
            name = Prompt.ask("Enter token name to delete")
            try:
                delete_token(name)
            except Exception as e:
                console.print(f"[red]Error deleting token: {e}[/red]")

        elif choice == "6":
            console.print("[bold green]👋 Exiting Vault CLI. Goodbye![/bold green]")
            break

if __name__ == "__main__":
    main()
