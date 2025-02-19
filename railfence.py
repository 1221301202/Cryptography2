# Rail Fence Cipher Implementation

def encrypt_rail_fence(text, depth):
    rail = [['\n' for i in range(len(text))] for j in range(depth)]
    
    row, direction = 0, 1
    for i in range(len(text)):
        rail[row][i] = text[i]
        row += direction
        if row == depth - 1 or row == 0:
            direction *= -1  

    ciphertext = ""
    for i in range(depth):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                ciphertext += rail[i][j]
    
    return ciphertext

def decrypt_rail_fence(ciphertext, depth):
    rail = [['\n' for i in range(len(ciphertext))] for j in range(depth)]
    
    row, direction = 0, 1
    for i in range(len(ciphertext)):
        rail[row][i] = '*'
        row += direction
        if row == depth - 1 or row == 0:
            direction *= -1

    index = 0
    for i in range(depth):
        for j in range(len(ciphertext)):
            if rail[i][j] == '*':
                rail[i][j] = ciphertext[index]
                index += 1

    plaintext = ""
    row, direction = 0, 1
    for i in range(len(ciphertext)):
        plaintext += rail[row][i]
        row += direction
        if row == depth - 1 or row == 0:
            direction *= -1

    return plaintext

# Run Rail Fence Cipher
if __name__ == "__main__":
    plaintext = "HELLOWORLD"
    depth = 3

    encrypted_text = encrypt_rail_fence(plaintext, depth)
    decrypted_text = decrypt_rail_fence(encrypted_text, depth)

    print("Rail Fence Encrypted Text:", encrypted_text)
    print("Rail Fence Decrypted Text:", decrypted_text)

import time
start = time.time()
encrypted_text = encrypt_rail_fence(plaintext, depth)
end = time.time()
print("Rail Fence Encryption Time:", end - start, "seconds")
