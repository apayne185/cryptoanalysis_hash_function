import string
import sys
import os
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'functions'))
from hash1 import simple_hash


#makes the random 8 char ASCII 
def random_string(length= 8):
    return ''.join(random.choices(string.printable[:94], k=length))


#checks if collision is found - will be a lot of attempts here
def find_collision():
    seen = {}
    attempts = 0

    while True:
        s= random_string()      #new random 8 char
        h = simple_hash(s)    #hashes it in hash1.yp
        attempts += 1

        #checks if its in dict - if yes
        if h in seen and seen[h] != s:
            print(f"Collision found with {attempts} attempts ")
            print(f"{seen[h]} -> {h}")
            print(f"{s} -> {h}")


            sol_path = os.path.join(os.path.dirname(__file__), '..', 'submissions', 'exercise03.txt')
            with open(sol_path, 'w') as f:
                f.write(f"{seen[h]},{s}")  

            print(f"Solution written to {sol_path}")
            return seen[h], s     #exits
        
        # if no, adds hash to dict and runs again
        seen[h] = s



if __name__ == '__main__':
    find_collision()