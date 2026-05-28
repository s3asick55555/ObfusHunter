# ObfusHunter

Static Windows malware obfuscation analyzer focused on five techniques:

1. String Encryption (XOR)
2. Import Obfuscation (dynamic API resolution)
3. PE Packing
4. Dead Code Insertion (opaque predicates / sink blocks)
5. API Hashing

## Run (Linux/macOS)

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
./run.sh
```

## Run (Windows)

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
run.bat
```

Open http://localhost:5000

## Notes

- This tool does not execute malware; it only inspects static PE artifacts.
- .NET/MSIL assemblies are out of scope for this analyzer.
