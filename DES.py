import argparse


def hex2bin(hexadecimal: str) -> str:
    val = int(hexadecimal, 16)
    val = bin(val)
    s = str(val)[2:]
    while len(s) < 64:
        s = '0' + s
    return s


def bin2hex(binary: str) -> str:
    val = int(binary, 2)
    val = hex(val)
    return str(val).upper()[2:]


def permute(k: str, arr: list, n: int) -> str:
    per = ""
    for i in range(n):
        per += k[arr[i] - 1]
    return per


def shift_left(k: str, shifts: int) -> str:
    s = ""
    for i in range(shifts):
        for j in range(1, 28):
            s += k[j]
        s += k[0]
        k = s
        s = ""
    return k


def xor(a: str, b: str) -> str:
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans += "0"
        else:
            ans += "1"
    return ans


# 16 rounds of Feistel encryption
def encrypt(plain_text: str, round_key_binary: list, round_key_hex: list) -> str:
    plain_text = hex2bin(plain_text)  # Hexadecimal to Binary

    # Initial Permutation Table, IP table, ex. [58] -> [1]
    initial_perm = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # Initial Permutation
    plain_text = permute(plain_text, initial_perm, 64)
    print("After initial permutation: " + bin2hex(plain_text))

    # Splitting plain text into two parts, each one has 32 bits
    left = plain_text[:32]
    right = plain_text[32:]
    print("After splitting: L0=" + bin2hex(left) + " R0=" + bin2hex(right))

    # Expansion Permutation Table
    exp_d = [
        32, 1, 2, 3, 4, 5, 4, 5,
        6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1
    ]

    # 8 S-boxes Table
    s_box = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    # P-box Permutation Table, FP table, [16] -> [1]
    p_box = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ]

    for i in range(16):
        # F-function Part
        # 1) Expansion Permutation for Right side
        right_expanded = permute(right, exp_d, 48)

        # 2) XOR K[i] and right_expanded
        x = xor(round_key_binary[i], right_expanded)

        # 3) S-box substitution
        op = ""
        for j in range(8):
            row = 2 * int(x[j * 6]) + int(x[j * 6 + 5])
            col = 8 * int(x[j * 6 + 1]) + 4 * int(x[j * 6 + 2]) + 2 * int(x[j * 6 + 3]) + int(x[j * 6 + 4])
            val = s_box[j][row][col]
            op += str(val // 8)
            val = val % 8
            op += str(val // 4)
            val = val % 4
            op += str(val // 2)
            val = val % 2
            op += str(val)

        # 4) P-box permutation
        op = permute(op, p_box, 32)

        # 5) XOR left and right
        x = xor(op, left)

        # give the result to L(i-1)
        left = x

        # swap right side and left side
        # Ri = L(i-i) & Li = R(i-1)
        if i != 15:
            left, right = right, left

        print("Round " + str(i + 1) + " " + bin2hex(left) + " " + bin2hex(right) + " " + round_key_hex[i])

    # Combination
    combine = left + right

    # Final Permutation Table
    final_perm = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]

    cipher = bin2hex(permute(combine, final_perm, 64))
    return cipher


# Main function, including Key Generation and Encryption
def main(plain_text: str, key: str):
    # Key Generation
    # Hex to binary
    key = hex2bin(key)

    # Parity bit drop table
    key_parity_drop_table = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    # getting 56 bit key from 64 bit using the parity bit drop table
    key = permute(key, key_parity_drop_table, 56)  # key without parity

    # Number of bit shifting
    # 16 Rounds total
    # Round #1, 2, 9, 16 are 2bits-shift, others are 1bit-shift
    shift_table = [
        1, 1, 2, 2,
        2, 2, 2, 2,
        1, 2, 2, 2,
        2, 2, 2, 1
    ]

    # Key- Compression Table 56bits to 48bits, permuted choice2
    key_comp = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]

    # Splitting the key into two 28bits-parts
    left = key[:28]
    right = key[28:]

    round_key_binary = []
    round_key_hex = []
    for i in range(16):
        # Shifting
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])

        # Combining
        combine = left + right

        # Key Compression, compress 56 bits key into 48 bits key
        round_key = permute(combine, key_comp, 48)

        # Add N-round key into the list in binary format
        round_key_binary.append(round_key)
        # Add N-round key into the list in hexadecimal format
        round_key_hex.append(bin2hex(round_key))

    # 16 rounds of Feistel encryption goes here, to line 47
    cipher = encrypt(plain_text, round_key_binary, round_key_hex)
    print("Cipher Text: " + cipher)
