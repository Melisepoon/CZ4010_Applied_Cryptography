from fractions import Fraction
from math import isqrt
import ast  # For parsing the public key file content
import time


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


def continued_fraction(numerator, denominator):
    """Generate the continued fraction representation of a fraction."""
    while denominator:
        quotient = numerator // denominator
        yield quotient
        numerator, denominator = denominator, numerator % denominator


def convergents(cf):
    """Generate the convergents of a continued fraction."""
    n0, n1 = 1, cf[0]
    d0, d1 = 0, 1
    yield (n1, d1)
    for q in cf[1:]:
        n2 = q * n1 + n0
        d2 = q * d1 + d0
        yield (n2, d2)
        n0, n1 = n1, n2
        d0, d1 = d1, d2


def is_perfect_square(num):
    """Check if a number is a perfect square."""
    root = isqrt(num)
    return root * root == num


def wieners_attack(e, n):
    """Perform Wiener's attack to find the private key d."""
    # Generate continued fraction representation of e/n
    cf = list(continued_fraction(e, n))

    # Generate convergents
    for k, d in convergents(cf):
        if k == 0 or d == 0:
            continue

        if (e * d - 1) % k != 0:
            continue
        phi_n = (e * d - 1) // k
        discriminant = (n - phi_n + 1) ** 2 - 4 * n

        if discriminant < 0 or not is_perfect_square(discriminant):
            continue

        root = isqrt(discriminant)
        p = (n - phi_n + 1 + root) // 2
        q = (n - phi_n + 1 - root) // 2

        if p * q == n:
            print(f"Found private key d: {d}")
            return d

    print("Wiener's attack failed.")
    return None


def decrypt_message(d, n, encrypted_list):
    """Decrypt a message using the private key."""
    try:
        # Ensure all elements are integers
        encrypted_list = [int(x) for x in encrypted_list]

        # Decrypt the list of integers
        decrypted_integers = [pow(ch, d, n) for ch in encrypted_list]
        print(f"Decrypted numbers: {decrypted_integers}")

        # Convert decrypted integers into a single string
        decrypted_message = ''
        for num in decrypted_integers:
            # Convert each decrypted number into bytes
            num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
            # Decode bytes into UTF-8 strings and concatenate
            decrypted_message += num_bytes.decode('utf-8', errors='replace')
        print(f"Decrypted message: {decrypted_message}")
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
    PUBLIC_KEY_FILE = "/Users/xingkun/Desktop/CZ4010_Applied_Cryptography-main/public_key.txt"
    ENCRYPTED_MESSAGE_FILE = "/Users/xingkun/Desktop/CZ4010_Applied_Cryptography-main/bid_messages.txt"

    # Load the public key
    e, n = load_public_key(PUBLIC_KEY_FILE)
    print(f"Loaded public key: e={e}, n={n}")

    overall_start_time = time.time()
    # Perform Wiener's attack
    d = wieners_attack(e, n)
    overall_elapsed_time = time.time() - overall_start_time

    if d:
        print(f"Recovered private key d: {d}")
        # Decrypt all messages from the file
        decrypted_messages = load_and_decrypt_all_messages(ENCRYPTED_MESSAGE_FILE, d, n)
        print("Decrypted all messages:")
        for i, msg in enumerate(decrypted_messages, start=1):
            print(f"Message {i}: {msg}")
    else:
        print("Failed to recover private key.")

    print(f"Total execution time: {overall_elapsed_time:.4f} seconds")