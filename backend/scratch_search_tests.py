import os

tests_dir = "C:\\Users\\kisho\\.gemini\\antigravity\\scratch\\vaultx\\backend\\tests"
for root, dirs, files in os.walk(tests_dir):
    for file in files:
        if file.endswith(".py"):
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                if "delete" in content or "drop" in content or "remove" in content:
                    print(f"Match found in {file}:")
                    for i, line in enumerate(content.splitlines()):
                        if any(kw in line for kw in ["delete", "drop", "remove"]):
                            print(f"  Line {i+1}: {line.strip()}")
