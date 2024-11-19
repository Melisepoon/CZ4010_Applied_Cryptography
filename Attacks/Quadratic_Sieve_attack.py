import time
import numpy as np
from sympy import isprime, mod_inverse
from sympy.ntheory import factorint
import ast


def load_public_key(file_path):
    """Load the public key (e, n) from a file."""
    try:
        with open(file_path, "r") as file:
            key_data = file.read()
            public_key = ast.literal_eval(key_data)  # Parse the key from string representation
            if isinstance(public_key, tuple) and len(public_key) == 2:
                return public_key
            else:
                raise ValueError("Invalid public key format.")
    except FileNotFoundError:
        print(f"Error: Public key file not found at {file_path}.")
        exit(1)
    except ValueError as e:
        print(f"Error: Invalid public key in file. {e}")
        exit(1)


def factorize_n(n):
    """Factorize the modulus n using sympy's factorint."""
    print(f"Attempting to factorize n={n} using sympy's factorint...")
    factorization = factorint(n)  # Get prime factors
    factors = list(factorization.keys())
    if len(factors) == 2:
        p, q = factors
        return p, q
    return None, None


def rsa_attack(e, n):
    """Perform RSA factorization attack and recover private key."""
    start_time = time.time()
    p, q = factorize_n(n)
    if not p or not q:
        print("Factorization failed.")
        return None

    print(f"Successfully factorized n: p={p}, q={q}")
    phi_n = (p - 1) * (q - 1)
    try:
        d = mod_inverse(e, phi_n)
        #print(f"Calculated private key d: {d}")
    except ValueError as err:
        print(f"Error in modular inverse calculation: {err}")
        return None

    elapsed_time = time.time() - start_time
    print(f"Factorization and key recovery took {elapsed_time:.4f} seconds")
    return d


def decrypt_message(d, n, encrypted_list):
    """Decrypt a message using the private key."""
    try:
        # Ensure all elements are integers
        encrypted_list = [int(x) for x in encrypted_list]

        # Decrypt the list of integers
        decrypted_integers = [pow(ch, d, n) for ch in encrypted_list]
        print(f"Encrypted numbers: {decrypted_integers}")

        # Convert decrypted integers into a single string
        decrypted_message = ''
        for num in decrypted_integers:
            # Convert each decrypted number into bytes
            num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
            # Decode bytes into UTF-8 strings and concatenate
            decrypted_message += num_bytes.decode('utf-8', errors='replace')
        #print(f"Decrypted message: {decrypted_message}")
        return decrypted_message
    except Exception as e:
        print(f"Decryption error: {e}")
        raise

def load_and_decrypt_all_messages(file_path, d, n):
    """Load and decrypt all encrypted messages from a file."""
    try:
        decrypted_messages = []
        with open(file_path, "r") as file:
            lines = file.readlines()
            # Iterate through all lines to find and decrypt messages
            for line in lines:
                if "Decrypted Message:" in line:
                    encrypted_data = line.split("Decrypted Message:")[1].strip()
                    try:
                        # Parse the encrypted message into a list of integers
                        encrypted_list = ast.literal_eval(encrypted_data)
                        # Decrypt the message
                        decrypted_message = decrypt_message(d, n, encrypted_list)
                        decrypted_messages.append(decrypted_message)
                    except Exception as e:
                        print(f"Error decrypting message: {e}")
                        continue
        if not decrypted_messages:
            raise ValueError("No valid encrypted messages found in the file.")
        return decrypted_messages
    except FileNotFoundError:
        print(f"Error: Encrypted message file not found at {file_path}.")
        exit(1)
    except ValueError as e:
        print(f"Error: Invalid encrypted message in file. {e}")
        exit(1)


if __name__ == "__main__":
    # Path to the public key file
    PUBLIC_KEY_FILE = "public_key.txt"
    ENCRYPTED_MESSAGE_FILE = "bid_messages.txt"
    # Load the public key
    e, n = load_public_key(PUBLIC_KEY_FILE)
    print ('################################ Quadratic Sieve (Start) ################################')
    print(f"\nLoaded public key: e={e}, \nn={n}")

    # Start the attack
    start_time = time.time()
    d = rsa_attack(e, n)
    elapsed_time = time.time() - start_time
    if d:
        print(f"Recovered private key d: {d}\n")
        # Decrypt all messages from the file
        decrypted_messages = load_and_decrypt_all_messages(ENCRYPTED_MESSAGE_FILE, d, n)
        print("\nDecrypted all messages:")
        for i, msg in enumerate(decrypted_messages, start=1):
            print(f"Message {i}: {msg}")
    else:
        print("Failed to recover private key.")

    print(f"Total execution time: {elapsed_time:.4f} seconds\n")
    print ('################################ Quadratic Sieve (End) ################################')