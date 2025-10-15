import pyodbc

# Connect to SQLite via ODBC
conn = pyodbc.connect(
    r"DRIVER={SQLite3 ODBC Driver};Database=C:\Users\hp\source\repos\Token\vault.db;Timeout=5;"
)

cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS hello(id INTEGER PRIMARY KEY, msg TEXT)")
cur.execute("INSERT INTO hello(msg) VALUES (?)", ("hi from ODBC",))
conn.commit()

cur.execute("SELECT * FROM hello")
print(cur.fetchall())

conn.close()
