import socket
from hash import keccak_hash
from rsa import RSA
import ast  # For safely parsing the public key file content

class Bidder:
    def __init__(self, public_key, host, port):
        self.rsa = RSA()
        self.rsa.e, self.rsa.n = public_key
        self.host = host  # Auctioneer's host
        self.port = port  # Auctioneer's port

    def get_bid_from_user(self):
        """Prompt the user to input their name and bid amount."""
        name = input("Enter your name: ")
        while True:
            try:
                price = int(input("Enter your bid amount: "))
                if price <= 0:
                    raise ValueError("Price must be a positive integer.")
                break
            except ValueError as e:
                print(f"Invalid input: {e}")
        hashed_name = keccak_hash(name)  # Hash the name
        bid_data = f"{hashed_name}:{price}"
        return bid_data

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
    bid = bidder.get_bid_from_user()
    encrypted_bid = bidder.encrypt_bid(bid)
    print(f"Your Bid: {bid}")
    #print(f"Encrypted Bid: {encrypted_bid}")

    # Send the encrypted bid to the auctioneer
    bidder.send_bid(encrypted_bid)