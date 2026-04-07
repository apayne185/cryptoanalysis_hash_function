import sys
import hashlib
import os

def usage():
    print("Usage: python sha256.py <input>")
    print("Produces the sha-2 256-bit digest of <input>. The output is in hex.")
    print()
    print("Example:")
    print("$ python sha256.py bitcoin")
    print("6b88c087247aa2f07ee1c5956b8e1a9f4c7f892a70e324f1bb3d161e05ca107b")



def find_prefix(prefix):
    i = 0        

    while True:
        s = f"bitcoin{i}"
        h = hashlib.sha256(s.encode('utf-8')).hexdigest()

        if h.startswith(prefix):
            print(f"Target {prefix} found! String: {s} -> Hash: {h[:10]}")
            return s
        i += 1


def main():
    targets = ['cafe', 'faded', 'decade']
    results = [] 

    for t in targets:
        print(f"Searching for prefix: {t} ")
        results.append(find_prefix(t))

    solution = ','.join(results)
    sol_path = os.path.join(os.path.dirname(__file__), '..', 'solutions', 'exercise06.txt')
    os.makedirs(os.path.dirname(sol_path), exist_ok=True)


    with open(sol_path, 'w') as f:
        f.write(solution)   


    print(f"\nSolution written to {sol_path}")
    print(f"Answer: {solution}")





if __name__ == '__main__':
    main()



# if __name__ == '__main__':
#     if len(sys.argv) != 2:
#         usage()
#         exit()
#     else:
#         s = sys.argv[1]
#         full_hash = hashlib.sha256(s.encode('utf-8')).hexdigest()
#         print(f"{full_hash}")
