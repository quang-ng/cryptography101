IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation (FP) table
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

def permute(block, table, in_size=64):
    """Generic permutation function for any size input."""
    permuted = 0
    for position in table:
        bit = (block >> (in_size - position)) & 1
        permuted = (permuted << 1) | bit
    return permuted

def initial_permutation(block):
    """Apply the initial permutation (IP) to a 64-bit block."""
    return permute(block, IP)

def final_permutation(block):
    """Apply the final permutation (FP) to a 64-bit block."""
    return permute(block, FP)


def expansion_function(R):
  """
  Expands a 32-bit block R into a 48-bit block using the DES expansion table.
  R: 32-bit integer
  Returns: 48-bit integer
  """
  E_TABLE = [
      32, 1, 2, 3, 4, 5,
       4, 5, 6, 7, 8, 9,
       8, 9,10,11,12,13,
      12,13,14,15,16,17,
      16,17,18,19,20,21,
      20,21,22,23,24,25,
      24,25,26,27,28,29,
      28,29,30,31,32, 1
  ]
  return permute(R, E_TABLE, 32)


def key_mixing(expanded_R, subkey):
    """
    XOR the expanded 48-bit R with the 48-bit round subkey.
    
    Parameters:
        expanded_R (int): 48-bit integer from Expansion function
        subkey (int): 48-bit round subkey
    
    Returns:
        int: 48-bit result of XOR
    """
    return expanded_R ^ subkey

S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [ 0, 15, 7, 4, 14, 2, 13, 1,10, 6, 12,11, 9, 5, 3, 8],
        [ 4, 1, 14, 8, 13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0],
        [15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13]
    ],
    # S2
    [
        [15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10],
        [ 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5],
        [ 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15],
        [13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9]
    ],
    # S3
    [
        [10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1],
        [13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7],
        [ 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12]
    ],
    # S4
    [
        [ 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15],
        [13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9],
        [10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4],
        [ 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14]
    ],
    # S5
    [
        [ 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9],
        [14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6],
        [ 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14],
        [11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11],
        [10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8],
        [ 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6],
        [ 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13]
    ],
    # S7
    [
        [ 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1],
        [13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6],
        [ 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2],
        [ 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7],
        [ 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2],
        [ 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8],
        [ 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11]
    ]
]

def sbox_substitution(input48):
    """
    Applies DES S-box substitution to a 48-bit input.
    Splits into 8 blocks of 6 bits, substitutes each using S1–S8.
    
    Parameters:
        input48 (int): 48-bit input after expansion and key mixing.
        
    Returns:
        int: 32-bit output from the 8 S-boxes
    """
    output32 = 0
    for i in range(8):
        # Extract 6-bit chunk
        six_bits = (input48 >> (42 - 6 * i)) & 0b111111

        # Get row (first and last bit), column (middle 4 bits)
        row = ((six_bits & 0b100000) >> 4) | (six_bits & 0b000001)
        col = (six_bits >> 1) & 0b1111

        # Get S-box value (4 bits)
        sbox_val = S_BOXES[i][row][col]

        # Append to output (shift left by 4 then OR)
        output32 = (output32 << 4) | sbox_val

    return output32


def left_rotate(val, shift, size):
    """Left circular shift"""
    return ((val << shift) & ((1 << size) - 1)) | (val >> (size - shift))

def key_schedule(key64):
    """
    Generate 16 DES subkeys (48-bit) from the 64-bit key.
    
    Parameters:
        key64 (int): 64-bit integer key
    
    Returns:
        List[int]: 16 round keys, each 48 bits
    """
    # Tables
    PC1 = [
        57,49,41,33,25,17, 9,
         1,58,50,42,34,26,18,
        10, 2,59,51,43,35,27,
        19,11, 3,60,52,44,36,
        63,55,47,39,31,23,15,
         7,62,54,46,38,30,22,
        14, 6,61,53,45,37,29,
        21,13, 5,28,20,12, 4
    ]
    PC2 = [
        14,17,11,24, 1, 5,
         3,28,15, 6,21,10,
        23,19,12, 4,26, 8,
        16, 7,27,20,13, 2,
        41,52,31,37,47,55,
        30,40,51,45,33,48,
        44,49,39,56,34,53,
        46,42,50,36,29,32
    ]
    LEFT_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2,
                   1, 2, 2, 2, 2, 2, 2, 1]

    # Step 1: Apply PC-1
    key56 = permute(key64, PC1, 64)
    C = (key56 >> 28) & ((1 << 28) - 1)
    D = key56 & ((1 << 28) - 1)

    round_keys = []
    for shift in LEFT_SHIFTS:
        # Step 2: Left shifts
        C = left_rotate(C, shift, 28)
        D = left_rotate(D, shift, 28)
        
        # Step 3: Combine and apply PC-2
        CD = (C << 28) | D
        Ki = permute(CD, PC2, 56)
        round_keys.append(Ki)

    return round_keys



def f_function(r32, k48):
    expanded = expansion_function(r32)
    xored = key_mixing(expanded_R=expanded, subkey=k48)
    substituted = sbox_substitution(xored)

    P_TABLE = [
        16, 7,20,21,29,12,28,17,
        1,15,23,26, 5,18,31,10,
        2, 8,24,14,32,27, 3, 9,
        19,13,30, 6,22,11, 4,25
    ]
    return permute(substituted, P_TABLE, 32)


def encrypt(plaintext, key):
    """
    Encrypts a 64-bit plaintext using DES.
    
    Parameters:
        plaintext (int): 64-bit integer plaintext
        key (int): 64-bit integer key
    
    Returns:
        int: 64-bit encrypted ciphertext
    """
    round_keys = key_schedule(key)

    permuted_plaintext = initial_permutation(plaintext)

    left = (permuted_plaintext >> 32) & 0xffffffff
    right = permuted_plaintext & 0xffffffff
    

    for i in range(16):
       left_next = right
       right = left ^ f_function(right, round_keys[i])
       left = left_next

    preoutput = (right << 32) | left  
    return final_permutation(preoutput)


def decrypt(ciphertext64, key64):
    """
    Decrypt a 64-bit ciphertext block with DES using a 64-bit key.

    Arguments:
        ciphertext64 (int): 64-bit ciphertext
        key64 (int): 64-bit DES key

    Returns:
        int: 64-bit plaintext
    """
    # Generate round keys in reverse order
    round_keys = key_schedule(key64)[::-1]

    # Initial permutation
    ip = permute(ciphertext64, IP, 64)
    L = (ip >> 32) & 0xFFFFFFFF
    R = ip & 0xFFFFFFFF

    for i in range(16):
        next_L = R
        R = L ^ f_function(R, round_keys[i])
        L = next_L

    # Final swap and inverse permutation
    preoutput = (R << 32) | L
    return final_permutation(preoutput)

key = 6423281134536131849

message = "🐱MEOW!!!"  # 8 characters max for 64 bits (1 byte per char)
plain_text = int.from_bytes(message.encode("utf-8"), 'big')

print("Original message:", message)
print("Plaintext (int):", plain_text)

# Encrypt & Decrypt
cipher_text = encrypt(plain_text, key)
decrypted = decrypt(cipher_text, key)

# Turn decrypted int back to string
recovered_msg = decrypted.to_bytes(8, 'big').decode("utf-8", errors="ignore")

print("\n🔐 Encrypted:", cipher_text)
print("🕵️ Decrypted message:", recovered_msg)

