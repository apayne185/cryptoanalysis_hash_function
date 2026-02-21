import sys

def simple_hash(s: str) -> str:
    hash_val = 0
    for char in s:
        hash_val = ((hash_val << 5) - hash_val + ord(char)) & 0xFFFFFFFF
    return f"{hash_val:08x}"

if __name__ == '__main__':
    if len(sys.argv) == 2:
        print(simple_hash(sys.argv[1]))
    else:
        print("Usage: python3 hash1.py <string>")