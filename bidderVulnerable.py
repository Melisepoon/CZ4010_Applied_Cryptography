import socket
import os
from hash import keccak_hash, md5_hash, sha256_hash,truncate_hash
from rsa import RSA
import ast  # For safely parsing the public key file content
# to truncate hash length to demonstrate vulnerability
BIT_SIZE = 16

class Bidder:
    USED_NAMES_FILE = "used_names.txt"  # Shared file for plaintext names

    def __init__(self, public_key, host, port):
        self.rsa = RSA()
        self.rsa.e, self.rsa.n = public_key
        self.host = host  # Auctioneer's host
        self.port = port  # Auctioneer's port

    # truncate hash of bid from user to designated bit size
    def get_bid_from_user_vulnerable(self):
        """Prompt the user to input their name and bid amount."""
        while True:
            name = input("Enter your name: ")
            if self.is_duplicate_name(name):
                print("This name has already been used. You are not eligible to bid.")
                continue  # Prompt for another name
            break

        while True:
            try:
                price = int(input("Enter your bid amount: "))
                if price <= 0:
                    raise ValueError("Price must be a positive integer.")
                break
            except ValueError as e:
                print(f"Invalid input: {e}")
            # Select the hash function to use
        print("Choose the hash function: 1) MD5, 2) SHA-256, 3) Keccak-256")
        choice = input("Enter your choice (1/2/3): ").strip()
        hash_function = md5_hash if choice == "1" else sha256_hash if choice == "2" else keccak_hash
        hashed_name = hash_function(name)  # Hash the name
        truncated_hashed_name = truncate_hash(hashed_name, BIT_SIZE)
        bid_data = f"{truncated_hashed_name}:{price}"
        return bid_data

    def is_duplicate_name(self, name):
        """Check if the plaintext name is already in the shared file."""
        if os.path.exists(self.USED_NAMES_FILE):
            with open(self.USED_NAMES_FILE, "r") as file:
                used_names = file.read().splitlines()
                if name in used_names:
                    return True

        # Add the name to the file if it's not a duplicate
        with open(self.USED_NAMES_FILE, "a") as file:
            file.write(name + "\n")
        return False
    
    def encrypt_bid(self, bid_data):
        """Encrypt the bid using the auctioneer's public key."""
        # Convert the bid data string into a list of encrypted integers
        encrypted_list = self.rsa.encrypt(bid_data)
        # Serialize the encrypted list as a comma-separated string
        encrypted_data = ','.join(map(str, encrypted_list))
        return encrypted_data

    def send_bid(self, encrypted_bid):
        """Send the encrypted bid to the auctioneer."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((self.host, self.port))
                # Send the serialized encrypted data
                client_socket.send(encrypted_bid.encode())  # Convert string to bytes
                print("Bid sent successfully.")
        except Exception as e:
            print(f"Error sending bid: {e}")

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

# Example Usage
if __name__ == "__main__":
    HOST = "127.0.0.1"  # Auctioneer's host
    PORT = 53140  # Auctioneer's port

    # Load the public key from the specified file
    PUBLIC_KEY_FILE = "public_key.txt"
    PUBLIC_KEY = load_public_key(PUBLIC_KEY_FILE)

    # Initialize a bidder
    bidder = Bidder(PUBLIC_KEY, HOST, PORT)

    # Get the bid from the user
    bid = bidder.get_bid_from_user_vulnerable()
    encrypted_bid = bidder.encrypt_bid(bid)
    print(f"Your Bid: {bid}")

    # Send the encrypted bid to the auctioneer
    bidder.send_bid(encrypted_bid)