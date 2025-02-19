from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def pause():
    input("\nPress Enter to continue...")

# ------------------ RSA Key Generation ------------------

def generate_rsa_keys():
    """
    Generates RSA key pair (private and public keys).
    """
    print("\nGenerating RSA Key Pair...")
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    print("\nPublic Key (Send to the other party):\n", public_key.decode())
    print("\nPrivate Key (Keep Secret!):\n", private_key.decode())

    pause()
    return private_key, public_key

# ------------------ RSA Encryption/Decryption ------------------

def rsa_encrypt(secret_key, public_key):
    """
    Encrypts the AES key using RSA public key.
    """
    print("\nEncrypting AES key using RSA...")
    try:
        recipient_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        encrypted_key = cipher_rsa.encrypt(secret_key)
        encrypted_key_b64 = base64.b64encode(encrypted_key).decode()
        print("Encrypted AES Key (Base64 Encoded):\n", encrypted_key_b64)
        pause()
        return encrypted_key_b64
    except ValueError as e:
        print("RSA Encryption Error:", e)
        return None

def rsa_decrypt(encrypted_key_b64, private_key):
    """
    Decrypts the AES key using RSA private key.
    """
    print("\nDecrypting AES key using RSA...")
    try:
        encrypted_key = base64.b64decode(encrypted_key_b64)
        recipient_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        decrypted_key = cipher_rsa.decrypt(encrypted_key)
        print("Decrypted AES Key:\n", decrypted_key.hex())
        pause()
        return decrypted_key
    except (ValueError, TypeError) as e:
        print("RSA Decryption Error:", e)
        return None

# ------------------ AES Encryption/Decryption ------------------

def aes_encrypt(message, secret_key):
    """
    Encrypts a message using AES (CBC mode) with PKCS7 padding.
    """
    print("\nEncrypting message using AES...")
    cipher = AES.new(secret_key, AES.MODE_CBC)
    iv = cipher.iv
    # Pad the message properly
    padded_message = pad(message.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_message)

    encrypted_data = base64.b64encode(iv + ciphertext).decode()
    print("Encrypted Message (Base64 Encoded):\n", encrypted_data)
    pause()
    return encrypted_data

def aes_decrypt(encrypted_data, secret_key):
    """
    Decrypts a message using AES (CBC mode) with PKCS7 unpadding.
    """
    print("\nDecrypting message using AES...")
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted_message = unpad(decrypted_padded, AES.block_size).decode()

        print("Decrypted Message:\n", decrypted_message)
        pause()
        return decrypted_message
    except (ValueError, UnicodeDecodeError) as e:
        print("AES Decryption Error:", e)
        return None

# ------------------ Bit Error Simulation ------------------

def simulate_bit_error(encrypted_data):
    """
    Introduces a bit error in the base64-encoded ciphertext.
    This example flips a bit in the first character.
    """
    # Convert the base64 string to a bytearray for mutation
    data_bytes = bytearray(encrypted_data, 'utf-8')
    # Flip the first bit of the first byte
    data_bytes[0] ^= 1
    return data_bytes.decode('utf-8', errors='ignore')

# ------------------ Hybrid Encryption Process ------------------

def hybrid_encrypt(message, public_key):
    """
    Encrypts the message using AES, then encrypts the AES key using RSA.
    """
    print("\n=== HYBRID ENCRYPTION PROCESS ===")
    pause()

    # Generate a random AES key (16 bytes for AES-128)
    secret_key = get_random_bytes(16)

    # Encrypt AES key using RSA
    encrypted_secret_key = rsa_encrypt(secret_key, public_key)
    if not encrypted_secret_key:
        return None, None  # Exit if RSA encryption fails

    # Encrypt message using AES
    encrypted_message = aes_encrypt(message, secret_key)

    # Simulate a bit error in the ciphertext to show error propagation
    print("\n--- Simulating Bit Error in the Encrypted Message ---")
    corrupted_encrypted_message = simulate_bit_error(encrypted_message)
    print("\nCorrupted Encrypted Message:\n", corrupted_encrypted_message)
    print("\n--- Attempting Decryption on Corrupted Ciphertext ---")
    _ = aes_decrypt(corrupted_encrypted_message, secret_key)

    return encrypted_secret_key, encrypted_message

def hybrid_decrypt(encrypted_secret_key, encrypted_message, private_key):
    """
    Decrypts the AES key using RSA, then decrypts the message using AES.
    """
    print("\n=== HYBRID DECRYPTION PROCESS ===")
    pause()

    # Decrypt AES key using RSA
    decrypted_secret_key = rsa_decrypt(encrypted_secret_key, private_key)
    if not decrypted_secret_key:
        return None  # Exit if RSA decryption fails

    # Decrypt message using AES
    decrypted_message = aes_decrypt(encrypted_message, decrypted_secret_key)

    return decrypted_message

# ------------------ Main Function ------------------

def main():
    print("Welcome to the Interactive Hybrid Cryptosystem (RSA + AES)!")

    mode = input("Type 'G' to generate RSA keys, 'E' for encryption, or 'D' for decryption: ").strip().upper()

    if mode == 'G':
        private_key, public_key = generate_rsa_keys()
        print("\n=== RSA Key Generation Complete ===")

    elif mode == 'E':
        print("\nPaste the recipient's RSA Public Key and type 'END' on a new line when done:")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        public_key = "\n".join(lines).encode()

        message = input("\nEnter the plaintext message to encrypt: ").strip()
        encrypted_secret_key, encrypted_message = hybrid_encrypt(message, public_key)

        if encrypted_secret_key and encrypted_message:
            print("\n=== ENCRYPTION COMPLETE ===")
            print("\nEncrypted AES Key (Send this to receiver):", encrypted_secret_key)
            print("\nEncrypted Message:", encrypted_message)
        else:
            print("\nEncryption Failed. Please try again.")

    elif mode == 'D':
        print("\nPaste your RSA Private Key and type 'END' on a new line when done:")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        private_key = "\n".join(lines).encode()

        encrypted_secret_key = input("\nEnter the encrypted AES key:\n").strip()
        encrypted_message = input("\nEnter the encrypted message:\n").strip()

        decrypted_message = hybrid_decrypt(encrypted_secret_key, encrypted_message, private_key)

        if decrypted_message:
            print("\n=== DECRYPTION COMPLETE ===")
            print("\nDecrypted Message:", decrypted_message)
        else:
            print("\nDecryption Failed. Please try again.")

    else:
        print("Invalid mode selected. Please choose 'G', 'E', or 'D'.")

if __name__ == "__main__":
    main()