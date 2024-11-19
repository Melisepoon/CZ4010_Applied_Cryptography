from sympy import isprime
from math import isqrt
import ast  # To safely parse the public key file content
import time 
from sympy.ntheory import pollard_rho
from math import isqrt
import ast
import time

def factorize_n(n):
    """Factorize the modulus n to find p and q using Pollard's Rho."""
    print("Using Pollard's Rho for factorization...")
    factor = pollard_rho(n)
    if factor:
        p = factor
        q = n // factor
        if isprime(p) and isprime(q):
            return p, q
    return None, None

# The rest of the code remains unchanged


def mod_inverse(e, phi_n):
    """Calculate the modular inverse of e mod phi_n."""
    original_phi = phi_n
    x0, x1 = 0, 1  # Coefficients for Extended Euclidean Algorithm
    while e > 1:
        q = e // phi_n
        e, phi_n = phi_n, e % phi_n
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += original_phi
    return x1


def rsa_factorization_attack(e, n):
    """Perform an RSA attack using pollard rho."""
    #print(f"Attempting to factorize n={n}...")
    p, q = factorize_n(n)
    if not p or not q:
        print("Factorization failed.")
        return None

    #print(f"Successfully factorized n: p={p}, q={q}")
    phi_n = (p - 1) * (q - 1)
    d = mod_inverse(e, phi_n)
    #print(f"Calculated private key d: {d}")
    return d


def load_public_key(file_path):
    """Load the public key (e, n) from a file."""
    try:
        with open(file_path, "r") as file:
            key_data = file.read()
            # Parse the key from string representation
            public_key = ast.literal_eval(key_data)
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

# Example Usage
if __name__ == "__main__":
    # Path to the public key file
    PUBLIC_KEY_FILE = "public_key.txt"
    ENCRYPTED_MESSAGE_FILE = "bid_messages.txt"
    # Load the public key
    e, n = load_public_key(PUBLIC_KEY_FILE)
    print ('################################ Pollard Rho (Start) ################################')
    print(f"Loaded public key: e={e}, n={n}\n")

    # Start the attack and measure time
    overall_start_time = time.time()
    d = rsa_factorization_attack(e, n)
    overall_elapsed_time = time.time() - overall_start_time
    if d:
        print(f"Recovered private key d: {d}\n")
        # Decrypt all messages from the file
        decrypted_messages = load_and_decrypt_all_messages(ENCRYPTED_MESSAGE_FILE, d, n)
        print("\nDecrypted all messages:")
        for i, msg in enumerate(decrypted_messages, start=1):
            print(f"Message {i}: {msg}")
    else:
        print("Failed to recover private key.")

    print(f"Total execution time: {overall_elapsed_time:.4f} seconds\n")
    print ('################################ Pollard Rho (End) ################################')