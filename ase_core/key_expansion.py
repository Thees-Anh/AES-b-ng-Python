# ase_core/key_expansion.py
# AES-128 Key Schedule — sinh 11 round keys từ key 128-bit (16 bytes)
# Theo chuẩn FIPS 197, Section 5.2

from ase_core.sbox import SBOX

# Round constants Rcon[1..10]
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _sub_word(word: list) -> list:
    """Áp dụng S-Box lên 4 bytes của một word."""
    return [SBOX[b] for b in word]


def _rot_word(word: list) -> list:
    """Xoay vòng trái 1 byte: [a0,a1,a2,a3] -> [a1,a2,a3,a0]."""
    return [word[1], word[2], word[3], word[0]]


def key_expansion(key: bytes) -> list:
    """
    Sinh 11 round keys từ key 128-bit.

    Input : key — 16 bytes
    Output: list gồm 11 round keys, mỗi round key là list 4 words,
            mỗi word là list 4 bytes.
            Tổng = 11 * 4 * 4 = 176 bytes.

    Ký hiệu:
        Nk = 4   (số words trong key)
        Nr = 10  (số rounds)
        Nb = 4   (số columns của state)
    """
    if len(key) != 16:
        raise ValueError("AES-128 yêu cầu key đúng 16 bytes")

    Nk = 4
    Nr = 10
    total_words = Nb = 4
    W = []  # mảng 44 words

    # --- Khởi tạo 4 word đầu từ key gốc ---
    for i in range(Nk):
        W.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])

    # --- Sinh các word còn lại ---
    for i in range(Nk, 4 * (Nr + 1)):
        temp = W[i - 1][:]
        if i % Nk == 0:
            # RotWord → SubWord → XOR Rcon
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[i // Nk]
        W.append([W[i - Nk][j] ^ temp[j] for j in range(4)])

    # --- Tổ chức thành 11 round keys, mỗi cái gồm 4 words ---
    round_keys = []
    for r in range(Nr + 1):
        round_keys.append(W[r*4 : r*4 + 4])

    return round_keys


def round_key_to_matrix(round_key: list) -> list:
    """
    Chuyển 1 round key (list 4 words, mỗi word 4 bytes)
    thành ma trận 4x4 theo thứ tự cột của AES state.

    round_key[col][row] -> matrix[row][col]
    """
    matrix = [[0]*4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            matrix[row][col] = round_key[col][row]
    return matrix
