import argparse
import hashlib

# Create a new ArgumentParser object
parser = argparse.ArgumentParser(description="Find the password of a hashed value using a word list")

# Add a "hash" argument that specifies the hash to find the password of
parser.add_argument("hash", help="The hashed value to find the password of")

# Add a "wordlist" argument that specifies the path to the word list
parser.add_argument("wordlist", help="The path to the word list file")

# Parse the command-line arguments
args = parser.parse_args()

# Verify which hash the user entered
if len(args.hash) == 32:
    hash_type = "md5"
elif len(args.hash) == 40:
    hash_type = "sha1"
elif len(args.hash) == 64:
    hash_type = "sha256"
else:
    # If the hash has an unsupported length, exit the program
    print("Error: unsupported hash type")
    exit()

# Open the word list file
with open(args.wordlist, "r") as wordlist_file:
    # Read each line in the file (i.e. each word in the list)
    for word in wordlist_file:
        # Strip the newline character from the end of the word
        word = word.strip()

        # Hash the word using the same hash function as the provided hash
        if hash_type == "md5":
            hashed_word = hashlib.md5(word.encode()).hexdigest()
        elif hash_type == "sha1":
            hashed_word = hashlib.sha1(word.encode()).hexdigest()
        elif hash_type == "sha256":
            hashed_word = hashlib.sha256(word.encode()).hexdigest()

        # Compare the hashed word to the provided hash
        if hashed_word == args.hash:
            # If they match, print the password and exit the program
            print("Password found:", word)
            exit()

# If the program reaches this point, it means no password was found
print("Password not found in word list")
