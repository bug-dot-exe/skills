# Injection Prevention — Python Patterns

## SQL Parameterization by Driver

```python
# sqlite3 — ? placeholders
conn.execute("SELECT * FROM users WHERE email = ?", (user_email,))

# psycopg2 (Postgres) — %s placeholders (driver-processed, NOT Python's %)
cur.execute("SELECT * FROM users WHERE email = %s", (user_email,))
cur.execute("SELECT * FROM users WHERE email = %(email)s", {"email": email})

# SQLAlchemy text() — :name placeholders
session.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})
```

**Gotcha:** psycopg2's `%s` is a driver placeholder, not Python's `%` operator.
Never mix `%` formatting with `execute()`.

## Deserialization RCE

```python
pickle.loads(user_bytes)    # DANGEROUS — executes arbitrary code
yaml.load(user_input)       # DANGEROUS — RCE with crafted YAML
yaml.load(data, Loader=yaml.FullLoader)  # DANGEROUS — still allows some objects
marshal.loads(user_bytes)   # DANGEROUS — never use on untrusted input

yaml.safe_load(user_input)  # Safe — basic types only
json.loads(user_input)      # Safe
```

Never deserialize untrusted data with pickle, marshal, or yaml.load.

## XXE with defusedxml

```python
from xml.etree.ElementTree import parse
tree = parse(user_xml)  # DANGEROUS — XXE, SSRF, billion-laughs DoS

import defusedxml.ElementTree as ET
tree = ET.parse(user_xml)  # Safe — blocks XXE, entity expansion, DTD
```

Always use `defusedxml` instead of stdlib `xml.*` for untrusted XML.

## Command Injection via subprocess

```python
import subprocess, shlex

subprocess.run(f"convert {user_file} out.png", shell=True)           # DANGEROUS
subprocess.run(["convert", user_file, "out.png"], check=True)        # Safe — no shell
subprocess.run(f"convert {shlex.quote(user_file)} out.png", shell=True)  # Last resort
```

`shell=False` (default) with a list of arguments is safe. `shlex.quote()` is
a last resort if shell=True is unavoidable.

## eval / exec — No Safe Way

```python
eval(user_input)                              # DANGEROUS — full expression eval
exec(user_input)                              # DANGEROUS — full statement exec
eval(user_input, {"__builtins__": {}})        # DANGEROUS — bypassable sandbox

import ast
value = ast.literal_eval(user_input)          # Safe — only literal values
```

There is no safe way to eval untrusted input. Use a purpose-built parser.
