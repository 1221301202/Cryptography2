# Playfair Cipher Implementation

def generate_playfair_matrix(key):
    key = key.replace("J", "I").upper()
    matrix = []
    used_chars = set()

    for char in key:
        if char not in used_chars and char.isalpha():
            matrix.append(char)
            used_chars.add(char)

    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in used_chars:
            matrix.append(char)
    
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, letter):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col
    return None

def preprocess_text(text):
    text = text.replace("J", "I").upper().replace(" ", "")
    processed_text = ""

    i = 0
    while i < len(text):
        char1 = text[i]
        char2 = text[i+1] if i+1 < len(text) else "X"
        if char1 == char2:
            processed_text += char1 + "X"
            i += 1
        else:
            processed_text += char1 + char2
            i += 2
    
    if len(processed_text) % 2 != 0:
        processed_text += "X"
    
    return processed_text

def encrypt_playfair(plaintext, matrix):
    plaintext = preprocess_text(plaintext)
    ciphertext = ""

    for i in range(0, len(plaintext), 2):
        row1, col1 = find_position(matrix, plaintext[i])
        row2, col2 = find_position(matrix, plaintext[i+1])

        if row1 == row2:
            ciphertext += matrix[row1][(col1+1) % 5] + matrix[row2][(col2+1) % 5]
        elif col1 == col2:
            ciphertext += matrix[(row1+1) % 5][col1] + matrix[(row2+1) % 5][col2]
        else:
            ciphertext += matrix[row1][col2] + matrix[row2][col1]

    return ciphertext

# Run Playfair Cipher
if __name__ == "__main__":
    key = "CIPHER"
    plaintext = "HELLO WORLD"
    matrix = generate_playfair_matrix(key)
    ciphertext = encrypt_playfair(plaintext, matrix)

    print("Playfair Encrypted Text:", ciphertext)


import time
start = time.time()
ciphertext = encrypt_playfair(plaintext, matrix)
end = time.time()
print("Playfair Encryption Time:", end - start, "seconds")
