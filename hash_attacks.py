import hashlib
import random
import string
from hash import keccak_hash, sha256_hash, md5_hash, truncate_hash

# Hash security (minimum secure bit size)
# Keccak --> 224 bits
# sha256 --> 256 bits
# md5 --> not secure at all regardless of hash size 
# md5 prone to collision attacks


# pre image resistant: have hash, try to find ORIGINAL input
# second preimage resistant: have hash, try to find another input that produces same hash

MAX_ATTEMPTS = 2**64//2

def load_and_truncate_hash(file_path, bits):
    """
    Load a hash from a file and truncate it to the specified bit length.
    Args:
        file_path: Path to the file containing the hash.
        bits: Number of bits to truncate the hash to.
    Returns:
        Truncated hash as a string.
    """
    try:
        with open("auction_results.txt", 'r') as file:
            for line in file:
                if line.startswith("Winner's Hash:"):
                    full_hash = line.split(":")[1].strip().split(",")[0]
                    return full_hash[:bits // 4]  # Convert bits to hex characters
        print("Hash not found in the file.")
        return None
    except FileNotFoundError:
        print("Hash file not found.")
        return None
    
# Brute force attack to find the original input that produces the given hash
# also known as second pre-image attack
# trying to find an input that produces given hash
# Procedure: try random inputs that give you the targeted hash
# to test brute force attack. numnber of attempts = 2^n/2, where n is the number of bits

def brute_force_attack(target_hash, hash_function, truncation_bits, max_attempts=MAX_ATTEMPTS):
    """
    Brute-force to find the input that produces the target hash (truncated).
    Args:
        target_hash: The truncated target hash to match.
        hash_function: The hash function to use (e.g., MD5, SHA-256, Keccak).
        truncation_bits: Number of bits to truncate the hash to.
        max_attempts: Maximum number of attempts.
    Returns:
        The matching input if found, otherwise None.
    """
    hash_length = truncation_bits // 4  # Convert bits to hex digits
    for attempt in range(max_attempts):
        candidate = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        computed_hash = hash_function(candidate)[:hash_length]
        # print(f"Attempt {attempt + 1}: Testing candidate: {candidate}, Hash: {computed_hash}")
        if computed_hash == target_hash:
            return candidate
    return None



# Birthday Attack (collision attack)
# finding 2 distinct input that hashes to the same value
def birthday_attack(hash_function, bits, max_attempts=MAX_ATTEMPTS):
    """Try to find two inputs that produce the same hash."""
    seen_hashes = {}
    for _ in range(max_attempts):
        candidate = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        hash_value = hash_function(candidate)[:bits // 4]
        if hash_value in seen_hashes:
            return seen_hashes[hash_value], candidate, hash_value
        seen_hashes[hash_value] = candidate
    return None

if __name__ == "__main__":
    # File containing the full hash
    hash_file = "auction_results.txt"
    
    # Hash size for truncation (e.g., 32 bits for demonstration)
    bits = int(input("Enter the bit size for truncation (e.g., 32): "))
    
    # Load and truncate hash
    truncated_hash = load_and_truncate_hash(hash_file, bits)
    if not truncated_hash:
        exit()
    
    print(f"Loaded and truncated hash: {truncated_hash}")
    
    # Select the hash function to use
    print("Choose the hash function: 1) MD5, 2) SHA-256, 3) Keccak-256")
    choice = input("Enter your choice (1/2/3): ").strip()
    hash_function = md5_hash if choice == "1" else sha256_hash if choice == "2" else keccak_hash
    
    # Perform brute force attack
    print("\nPerforming Brute-Force Attack...")
    result = brute_force_attack(truncated_hash, hash_function, bits)
    if result:
        print(f"Brute-force attack succeeded! Input: {result}")
    else:
        print("Brute-force attack failed.")

    # test brute for input
    verify_result = hash_function(result)
    truncate_result = truncate_hash(verify_result,bits)
    print(f"Verify hash:  {truncate_result}")
    
    
    # Perform birthday attack
    print("\nPerforming Birthday Attack...")
    result = birthday_attack(hash_function, bits)
    if result:
        input1, input2, collision_hash = result
        print(f"Birthday attack succeeded! Input1: {input1}, Input2: {input2}, Hash: {collision_hash}")
    else:
        print("Birthday attack failed.")
