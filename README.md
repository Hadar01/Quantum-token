# Quantum-token

A small collection of token generation and secure storage experiments. The repo includes:

- **Token generation** using cryptographically secure randomness, hashing, and RSA encryption.
- **Token vault demos** that store and retrieve encrypted tokens with audit logging.
- **CLI workflow** for generating tokens and persisting them in a local database.

## Repository layout

```
.
├── README.md
├── Token/
│   ├── tokenGen.py
│   ├── vault_cli.py
│   ├── vault_demo.py
│   ├── vault_with_tokenGen.py
│   └── vault.db
└── Tokenization/
    ├── Token_Generation.ipynb
    └── tokenGen.py
```

### Key scripts

- `Token/tokenGen.py` — Generates a secure token by hashing random material and encrypting it with RSA.
- `Token/vault_cli.py` — Interactive CLI that generates tokens, encrypts them with a master key, stores them in SQL Server LocalDB, and records audit logs.
- `Token/vault_demo.py` — Minimal SQLite demo of storing/retrieving tokens with audit logging.
- `Token/vault_with_tokenGen.py` — Uses the token generator and stores the result in the SQLite vault.
- `Tokenization/tokenGen.py` — Notebook-friendly generator variant used in `Tokenization/Token_Generation.ipynb`.

## Requirements

- **Python 3.9+** (tested with standard CPython tools)
- **Python packages**:
  - `cryptography`
  - `sqlalchemy`
  - `pyodbc` (required for the LocalDB CLI)
  - `rich`
  - `pyfiglet`

Install dependencies:

```bash
pip install cryptography sqlalchemy pyodbc rich pyfiglet
```

## Setup

### 1) Configure the master key

The vault workflows require a master key for envelope encryption. Generate one with `cryptography` and set it as `MASTER_KEY`.

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set the environment variable (PowerShell example):

```powershell
setx MASTER_KEY "<paste-key-here>"
```

Restart your shell after setting it.

### 2) LocalDB (for `vault_cli.py`)

`vault_cli.py` uses SQL Server LocalDB via ODBC. Install a SQL Server ODBC driver (18 or 17) and ensure the `sqllocaldb` utility is available on your system.

> Note: `vault_demo.py` and `vault_with_tokenGen.py` use SQLite and do **not** require LocalDB.

## Usage

### Generate a token (standalone)

```bash
python Token/tokenGen.py
```

### Run the vault CLI (LocalDB + ODBC)

```bash
python Token/vault_cli.py
```

Menu options include generating/storing tokens, retrieval, listing, and auditing.

### Run the SQLite demo

```bash
python Token/vault_demo.py
```

### Generate + store a token with SQLite

```bash
python Token/vault_with_tokenGen.py
```

## Security notes

- Tokens are encrypted with RSA for generation demos and stored using envelope encryption with `Fernet` for the vault.
- The `MASTER_KEY` protects per-token data encryption keys; keep it secret and rotate if compromised.

## Troubleshooting

- **`MASTER_KEY not set`**: ensure the environment variable is set in the current shell session.
- **ODBC driver not found**: install ODBC Driver 18 or 17 for SQL Server and re-run the CLI.
- **LocalDB missing**: install SQL Server LocalDB or use the SQLite demos instead.
