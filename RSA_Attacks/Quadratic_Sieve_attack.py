from math import isqrt
import ast
import time


def load_public_key(file_path):
    """Load the public key (e, n) from a file."""
    try:
        with open(file_path, "r") as file:
            key_data = file.read()
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


def extract_ciphertext(file_path):
    """Extract the ciphertext from the encrypted message file."""
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
            for line in lines:
                if "Decrypted Message:" in line:
                    # Extract the encrypted message after "Decrypted Message:"
                    encrypted_data = line.split("Decrypted Message:")[1].strip()
                    # Parse the encrypted message into a list of integers
                    return ast.literal_eval(encrypted_data)
    except FileNotFoundError:
        print(f"Error: Encrypted message file not found at {file_path}.")
        exit(1)
    except ValueError as e:
        print(f"Error: Invalid encrypted message in file. {e}")
        exit(1)


def last_two_digits_mod100(c, e):
    """Compute the last two digits of the plaintext using mod 100."""
    try:
        # Reduce ciphertext to mod 100
        c_mod_100 = c % 100

        # Modular exponentiation to compute m mod 100
        m_mod_100 = pow(c_mod_100, e, 100)

        return m_mod_100
    except Exception as e:
        print(f"Error computing last two digits with mod 100: {e}")
        return None


if __name__ == "__main__":
    # Path to the public key and encrypted message files
    PUBLIC_KEY_FILE = "public_key.txt"
    ENCRYPTED_MESSAGE_FILE = "bid_messages.txt"

    # Load the public key
    e, n = load_public_key(PUBLIC_KEY_FILE)
    print("################################ Mod 100 Decryption (Start) ################################")
    print(f"\nLoaded public key: e={e}, \nn={n}")

    # Extract the ciphertext from the encrypted message file
    ciphertext_list = extract_ciphertext(ENCRYPTED_MESSAGE_FILE)
    if not ciphertext_list:
        print("No ciphertext found in the encrypted message file.")
        exit(1)

    # Compute the last two digits for each ciphertext
    for i, c in enumerate(ciphertext_list, start=1):
        print(f"\nProcessing ciphertext {i}: {c}")
        overall_start_time = time.time()

        # Compute last two digits using the mod 100 method
        last_two_digits = last_two_digits_mod100(c, e)

        if last_two_digits is not None:
            print(f"The last two digits of the plaintext are: {last_two_digits}")
        else:
            print("Failed to compute the last two digits.")

        overall_elapsed_time = time.time() - overall_start_time
        print(f"Execution time for ciphertext {i}: {overall_elapsed_time:.4f} seconds\n")

    print("################################ Mod 100 Decryption (End) ################################")