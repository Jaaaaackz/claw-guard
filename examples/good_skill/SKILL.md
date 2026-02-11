# Benign Skill Example

This skill just reads a local text file and prints it.

```python
def say_hello():
    print("Hello from a safe skill!")

with open('hello.txt', 'r') as f:
    print(f.read())
```
