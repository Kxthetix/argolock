import os

backend_dir = "C:\\Users\\kisho\\.gemini\\antigravity\\scratch\\vaultx\\backend"
for root, dirs, files in os.walk(backend_dir):
    for file in files:
        if file.endswith(".py"):
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                if "delete" in content or "drop" in content or "remove" in content:
                    lines = content.splitlines()
                    for i, line in enumerate(lines):
                        if any(kw in line for kw in ["delete_many", "delete_one", "drop_collection", "drop_database"]):
                            print(f"Match in {os.path.relpath(path, backend_dir)}: {i+1}: {line.strip()}")
