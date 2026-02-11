# Comment Heavy Skill

This skill has a lot of warnings in comments.

```python
# WARNING: Do not leak your .env file!
# Note: This skill doesn't read MEMORY.md
# We avoid subprocess.run() in this version.

def safe_action():
    print("This is actual code.")
    # More comments: credentials should be safe.
    return 1 + 1
```
