import argparse
import hashlib
import os
import threading
import time

def find_password(hash_value, wordlist_path, hash_type):
    if hash_type == "md5":
        hash_func = hashlib.md5
        hash_length = 32
    elif hash_type == "sha1":
        hash_func = hashlib.sha1
        hash_length = 40
    elif hash_type == "sha256":
        hash_func = hashlib.sha256
        hash_length = 64
    else:
        print("Error: unsupported hash type")
        return

    if len(hash_value) != hash_length:
        print("Error: Hash length doesn't match the specified hash type")
        return

    if not os.path.isfile(wordlist_path):
        print("Error: Wordlist file not found")
        return

    with open(wordlist_path, "r") as wordlist_file:
        for word in wordlist_file:
            word = word.strip()
            hashed_word = hash_func(word.encode()).hexdigest()
            if hashed_word == hash_value:
                print("Password found:", word)
                return

    print("Password not found in word list")

def crack_password(hash_file, wordlist_file, hash_type, num_threads, processed_hashes):
    if not os.path.isfile(hash_file):
        print("Error: Hash file not found")
        return

    threads = []

    def crack_hashes(hash_lines):
        for line in hash_lines:
            hash_value = line.strip()
            if hash_value not in processed_hashes:
                find_password(hash_value, wordlist_file, hash_type)
                processed_hashes.add(hash_value)
                print("Cracking hash:", hash_value)

    with open(hash_file, "r") as hashfile:
        hash_lines = hashfile.readlines()
        chunk_size = len(hash_lines) // num_threads

        for i in range(num_threads):
            start = i * chunk_size
            end = start + chunk_size if i < num_threads - 1 else len(hash_lines)
            thread = threading.Thread(target=crack_hashes, args=(hash_lines[start:end],))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

def main():
    parser = argparse.ArgumentParser(description="Crack hashed passwords using a wordlist and multi-threading")
    parser.add_argument("wordlist_file", help="The path to the wordlist file")
    parser.add_argument("--hash-type", choices=["md5", "sha1", "sha256"], default="md5", help="Specify the hash type (default: md5)")
    parser.add_argument("--threads", type=int, default=1, help="Specify the number of threads to use (default: 1)")
    parser.add_argument("--hash-file", help="The path to the hash file (default: hash.txt)")
    parser.add_argument("--wordlist-path", help="The path to the wordlist file (default: wordlist.txt)")

    args = parser.parse_args()

    hash_file = args.hash_file if args.hash_file else "hash.txt"
    wordlist_file = args.wordlist_path if args.wordlist_path else "wordlist.txt"

    processed_hashes = set()

    while True:
        with open(hash_file, "r") as hashfile:
            hash_lines = hashfile.readlines()

        if not hash_lines:
            print("No more hashes found in", hash_file)
            break

        # Remove hashes that have already been processed
        new_hash_lines = [line for line in hash_lines if line.strip() not in processed_hashes]
        if not new_hash_lines:
            print("All hashes have been processed.")
            break

        crack_password(hash_file, wordlist_file, args.hash_type, args.threads, processed_hashes)

        time.sleep(5)  # Adjust the delay (in seconds) between each loop iteration as needed

if __name__ == "__main__":
    main()
