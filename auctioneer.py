import random
import string
import socket
import threading
from rsa import RSA
from hash import keccak_hash
import time

# Define global constants
MIN_PRIME = 2**80
MAX_PRIME = 2**81 - 1
BITS = 16
HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 53140  # Port to listen on (non-privileged ports are > 1023)
AUCTION_DURATION = 30  # Auction duration in seconds

class Auctioneer:
    def __init__(self):
        self.rsa = RSA()
        self.public_key = None
        self.private_key = None
        self.host = HOST
        self.port = PORT
        self.bids = []  # List to store received bids
        self.auction_active = True
        self.server_socket = None  # Server socket for shutting down
    
    def generate_keys(self):
        print("################################ Auction Start ################################")
        """Generate the auctioneer's public and private RSA keys using the global min and max prime values."""
        self.public_key, self.private_key = self.rsa.generate_keysv2(BITS)
        print("Auctioneer's Public Key {e,n}:", self.public_key)
        self.write_public_key_to_file()
    
    def write_public_key_to_file(self):
        """Write the public key to a file."""
        with open("public_key.txt", "w") as file:
            file.write(str(self.public_key))
        print("Public key written to public_key.txt")
    
    def start_server(self):
        """Start the auctioneer's server to listen for incoming bids."""
        print("Starting auctioneer server...")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Auctioneer is listening on {self.host}:{self.port}...")
        
        # Start a timer to end the auction after a fixed duration
        timer = threading.Timer(AUCTION_DURATION, self.end_auction)
        timer.start()

        while self.auction_active:
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"Received connection from {client_address}")
                thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                thread.start()
            except OSError:
                break  # Server socket was closed, exit loop
    
    def handle_client(self, client_socket):
        """Handle incoming bids from clients."""
        try:
            # Receive the encrypted message as bytes
            encrypted_data = client_socket.recv(4096).decode()  # Decode the bytes into a string
            #print(f"Received encrypted data: {encrypted_data}")
            print ('Received data: ',encrypted_data)
            # Deserialize the encrypted string into a list of integers
            encrypted_list = list(map(int, encrypted_data.split(',')))  # Convert strings to integers
            #print(f"Deserialized encrypted list: {encrypted_list}")

            # Decrypt the bid
            decrypted_bid = self.decrypt_bid(encrypted_list)
            #print(f"Decrypted bid received: {decrypted_bid}")
            with open("bid_messages.txt", "a") as file:
                file.write(f"Decrypted Message: {encrypted_list}\n")
            # Parse the decrypted bid
            hashed_name, price = decrypted_bid.split(":")
            price = int(price)

            # Store the bid for later processing
            self.bids.append((hashed_name, price))
            print(f"Stored bid: Hashed Name: {hashed_name}, Price: {price}\n")

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    #changed
    def decrypt_bid(self, encrypted_list):
        """Decrypt a bid using the auctioneer's private key."""
        if not self.private_key:
            raise ValueError("Private key not generated. Call generate_keys first.")
        try:
            # Ensure all elements are integers
            encrypted_list = [int(x) for x in encrypted_list]

            # Decrypt the list of integers
            decrypted_integers = self.rsa.decrypt(encrypted_list)
            #print(f"Decrypted numbers: {decrypted_integers}")

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
    
    def end_auction(self):
        """End the auction and determine the winner."""
        self.auction_active = False
        print("Auction ended. Determining winner...")
        if self.server_socket:
            self.server_socket.close()  # Stop the server
        if not self.bids:
            print("No bids received.")
            return
        self.bids.sort(key=lambda x: x[1], reverse=True)
        winner_hash, winning_price = self.bids[0]
        second_highest_price = self.bids[1][1] if len(self.bids) > 1 else winning_price
        print(f"Winner's Hash: {winner_hash}, Winning Price: {second_highest_price}")
        with open("auction_results.txt", "w") as file:
            file.write(f"Winner's Hash: {winner_hash}, Winning Price: {second_highest_price}\n")
        print("Auction results written to auction_results.txt")

    def clear_message_file(self, file_path):
        """Clear all content in the specified file."""
        with open(file_path, "w") as file:
            pass  # Opening in write mode clears the file

# Main Execution
if __name__ == "__main__":
    auctioneer = Auctioneer()
    
    # Path to the file storing received bids
    BID_MESSAGES_FILE = "bid_messages.txt"

    # Clear the file before starting a new auction
    auctioneer.clear_message_file(BID_MESSAGES_FILE)

    auctioneer.generate_keys()
    auctioneer.start_server()
