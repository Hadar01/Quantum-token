# odbc_selftest.py
import re, subprocess, sys
import pyodbc

def choose_driver():
    ds = [d.lower() for d in pyodbc.drivers()]
    for name in ("odbc driver 18 for sql server", "odbc driver 17 for sql server", "sql server"):
        if name in ds:
            return [d for d in pyodbc.drivers() if d.lower() == name][0]
    raise RuntimeError("No SQL Server ODBC driver found")

def ensure_instance():
    try:
        subprocess.check_call(["sqllocaldb","start","MSSQLLocalDB"])
    except subprocess.CalledProcessError:
        subprocess.check_call(["sqllocaldb","create","MSSQLLocalDB"])
        subprocess.check_call(["sqllocaldb","start","MSSQLLocalDB"])

def localdb_pipe():
    out = subprocess.check_output(["sqllocaldb","info","MSSQLLocalDB"], text=True)
    m = re.search(r"Instance pipe name:\s*(\S+)", out)
    return m.group(1) if m else None

def try_connect(driver, server):
    cs = f"DRIVER={{{driver}}};SERVER={server};Trusted_Connection=Yes;Encrypt=No;DATABASE=master"
    with pyodbc.connect(cs) as conn:
        cur = conn.cursor()
        print("select 1 =>", cur.execute("select 1").fetchone())

def main():
    print("Drivers:", pyodbc.drivers())
    driver = choose_driver()
    print("Using driver:", driver)
    ensure_instance()
    try:
        try_connect(driver, r"(localdb)\MSSQLLocalDB")
        print("Instance connection OK")
    except Exception as e:
        print("Instance connect failed:", e)
        pipe = localdb_pipe()
        if not pipe:
            print("No pipe found; run: sqllocaldb info MSSQLLocalDB")
            sys.exit(1)
        try_connect(driver, f"np:{pipe}\\tsql\\query")
        print("Pipe connection OK")

if __name__ == "__main__":
    main()
