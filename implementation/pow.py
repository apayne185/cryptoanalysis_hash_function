import hashlib
import os


def find_prefix(prefix):
    i = 0

    while True:
        s = f"bitcoin{i}"
        h = hashlib.sha256(s.encode('utf-8')).hexdigest()  

        if h.startswith(prefix):
            print(f"  '{s}' -> {h[:len(prefix)+4]}... (after {i+1} attempts)")
            return s
        i += 1


def main():
    targets = ['cafe', 'faded','decade']   
    results = []   #winners
    for t in targets:
        print(f"Finding SHA256 starting with '{t}'...")
        results.append(find_prefix(t))

    solution = ','.join(results)
    sol_path = os.path.join(os.path.dirname(__file__), '..', 'submissions', 'exercise06.txt')
    with open(sol_path, 'w') as f:
        f.write(solution)

    print(f"\nSolution written to {sol_path}")
    print(f"Answer: {solution}")





if __name__ == '__main__':
    main()