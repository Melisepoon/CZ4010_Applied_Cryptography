import random
import math
import secrets
from sympy import isprime


# e has to start from 3
# if e = 1, encryption is meaningless, anything to power 1 = itself
# e has to be odd, because phi_n = (p-1)*(q-1) --> is always even, bcos p/q are odd, -1 is even
# and if e were even together with phi_n, gcd(e,phi_n) != 1
# can try using e = 65537 as default
# format for public key {e,n}
# format for private key {d,n}

# ToDo:
# Add in function to check size of decryption key > 1/3 * N^1/4
# Attacks


class RSA:
    def __init__(self):
        # # Generate two distinct primes p and q
        # self.p = self.generate_prime(min_prime, max_prime)
        # self.q = self.generate_prime(min_prime, max_prime)
        # while self.p == self.q:  # Ensure p and q are distinct
        #     self.q = self.generate_prime(min_prime, max_prime)
        
        # # Calculate n and phi_n
        # self.n = self.p * self.q
        # self.phi_n = (self.p - 1) * (self.q - 1)
        
        # # Generate the public key (e) and private key (d)
        # self.e = self.generate_e()
        # self.d = self.mod_inverse(self.e, self.phi_n)
        self.p = None
        self.q = None
        self.n = None
        self.phi_n = None
        self.e = None
        self.d = None

    def is_prime(self, number):
        """Check if a number is prime."""
        if number < 2:
            return False
        for i in range(2, number // 2 + 1):
            if number % i == 0:
                return False
        return True

    def generate_prime(self, min_value, max_value):
        """Generate a random prime number within the specified range."""
        prime = random.randint(min_value, max_value)
        while not self.is_prime(prime):
            prime = random.randint(min_value, max_value)
        return prime
    
    def generate_secure_prime(self,bits):
        while True:
            candidate = secrets.randbits(bits)
            if isprime(candidate):
                return candidate

    # to obtain decryption key
    # this is iteration approach, may have high overheads
    # look into Extended Euclid Algorithm for lower overhead in generating
    def mod_inverse(self, e, phi_n):
        # """Calculate the modular inverse of e mod phi_n.
        # takes O(phi_n) time
        # """
        # for d in range(3, phi_n):
        #     if (d * e) % phi_n == 1:
        #         return d
        # raise ValueError("mod_inverse does not exist")
        """
        Calculate the modular inverse of e mod phi_n using the Extended Euclidean Algorithm.
        takes O(log(phi_n)) time
        """
        original_phi = phi_n
        x0, x1 = 0, 1  # Coefficients for the Extended Euclidean Algorithm
        while e > 1:
            # Compute quotient
            q = e // phi_n
            # Update e and phi_n (similar to the Euclidean algorithm)
            e, phi_n = phi_n, e % phi_n
            # Update coefficients
            x0, x1 = x1 - q * x0, x0
        # If e becomes 1, x1 is the modular inverse, but ensure it's positive
        if x1 < 0:
            x1 += original_phi
        return x1

    def generate_e(self):
        """Generate a public exponent e."""
        e = random.randint(3, self.phi_n - 1)
        while math.gcd(e, self.phi_n) != 1:
            e = random.randint(3, self.phi_n - 1)
        return e
    
    def generate_keys(self, min_value=1000, max_value=5000):
        self.p = self.generate_prime(min_value, max_value)
        self.q = self.generate_prime(min_value, max_value)
        while self.p == self.q:
            self.q = self.generate_prime(min_value, max_value)

        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)

        self.e = self.generate_e()
        self.d = self.mod_inverse(self.e, self.phi_n)
        return (self.e, self.n), (self.d, self.n)

    #faster version to generate keys
    def generate_keysv2(self,bits):
        self.p = self.generate_secure_prime(bits)
        self.q = self.generate_secure_prime(bits)
        while self.p == self.q:
            self.q = self.generate_secure_prime(bits)

        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)

        self.e = self.generate_e()
        self.d = self.mod_inverse(self.e, self.phi_n)
        return (self.e, self.n), (self.d, self.n)

    def encrypt(self, plaintext):
        """
        Encrypt a plaintext message.
        Args:
            plaintext (str): The message to be encrypted.
        Returns:
            list: The encrypted message as a list of integers.
        """
        # make message ASCII character  
        message_encoded = [ord(ch) for ch in plaintext]
        # c = (m^e) mod n
        # encrypting in per character basis, bcos require m<n
        # this is a list
        cipher_text = [pow(ch, self.e, self.n) for ch in message_encoded]
        return cipher_text

    def decrypt(self, cipher_text):
        """
        Decrypt a cipher text message.
        Args:
            cipher_text (list): The encrypted message as a list of integers.
        Returns:
            list: The decrypted message as a list of integers.
        """
        if not isinstance(cipher_text, list):
            raise ValueError("Input to decrypt must be a list of integers.")
        try:
            # Decrypt each integer in the cipher text
            message_encoded = [pow(ch, self.d, self.n) for ch in cipher_text]
            return message_encoded  # Return as a list of integers
        except Exception as e:
            print(f"Error in RSA decryption: {e}")
            raise

    def get_public_key(self):
        """Return the public key."""
        return self.e, self.n

    #secret
    def get_private_key(self):
        """Return the private key (for testing/debugging purposes)."""
        return self.d
    
    #secret
    def get_pq_phi(self):
        """Return p,q, phi_n (for testing/debugging purposes)."""
        return self.p, self.q, self.phi_n

# Example Usage
rsa = RSA()

# Generate a 512-bit prime number
# prime_number = rsa.generate_secure_prime(256)
# print(prime_number)

# rsa.generate_keys(min_value=1000, max_value=5000)

# print("{p,q, phi_n}: ", rsa.get_pq_phi()) #secret
# print("Public Key {e,n}: ", rsa.get_public_key())
# print("Private Key, d (for testing):", rsa.get_private_key()) #secret

# message = "Hello World"
# print("\nOriginal Message:", message)

# # Encrypt
# cipher_text = rsa.encrypt(message)
# print("Encrypted Message:", cipher_text)

# # Decrypt
# decrypted_message = rsa.decrypt(cipher_text)
# print("Decrypted Message:", decrypted_message)
