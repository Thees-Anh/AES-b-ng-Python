# ase_core/aes.py
# AES-128 — 4 phép biến đổi round + encrypt/decrypt block + CBC mode
# Không dùng thư viện crypto, tự implement từ đầu theo FIPS 197

from ase_core.sbox import SBOX, INV_SBOX
from ase_core.galois import gmul
from ase_core.key_expansion import key_expansion, round_key_to_matrix
from file_handler.padding import pad, unpad
import os

# ──────────────────────────────────────────────
# Helpers: bytes <-> state matrix (4x4)
# AES state: 4 hàng, 4 cột, lưu theo CỘT (column-major)
# state[row][col]
# ──────────────────────────────────────────────

def _bytes_to_state(block: bytes) -> list:
    """Chuyển 16 bytes thành ma trận 4x4 (column-major)."""
    state = [[0]*4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = block[col*4 + row]
    return state


def _state_to_bytes(state: list) -> bytes:
    """Chuyển ma trận 4x4 về 16 bytes (column-major)."""
    result = []
    for col in range(4):
        for row in range(4):
            result.append(state[row][col])
    return bytes(result)


# ──────────────────────────────────────────────
# Bước 1: SubBytes — thay thế từng byte qua S-Box
# ──────────────────────────────────────────────

def _sub_bytes(state: list) -> list:
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _inv_sub_bytes(state: list) -> list:
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


# ──────────────────────────────────────────────
# Bước 2: ShiftRows — xoay vòng trái từng hàng
# Hàng 0: không xoay | Hàng 1: 1 | Hàng 2: 2 | Hàng 3: 3
# ──────────────────────────────────────────────

def _shift_rows(state: list) -> list:
    return [
        state[0],                                                    # hàng 0: giữ nguyên
        [state[1][1], state[1][2], state[1][3], state[1][0]],       # hàng 1: xoay 1
        [state[2][2], state[2][3], state[2][0], state[2][1]],       # hàng 2: xoay 2
        [state[3][3], state[3][0], state[3][1], state[3][2]],       # hàng 3: xoay 3
    ]


def _inv_shift_rows(state: list) -> list:
    return [
        state[0],
        [state[1][3], state[1][0], state[1][1], state[1][2]],       # hàng 1: xoay phải 1
        [state[2][2], state[2][3], state[2][0], state[2][1]],       # hàng 2: xoay phải 2
        [state[3][1], state[3][2], state[3][3], state[3][0]],       # hàng 3: xoay phải 3
    ]


# ──────────────────────────────────────────────
# Bước 3: MixColumns — nhân ma trận trong GF(2^8)
# Mỗi cột nhân với ma trận cố định của AES
# ──────────────────────────────────────────────

def _mix_single_column(col: list) -> list:
    """Nhân 1 cột (4 bytes) với ma trận MixColumns."""
    s0, s1, s2, s3 = col
    return [
        gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3,
        s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3,
        s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3),
        gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3),
    ]


def _inv_mix_single_column(col: list) -> list:
    """Nhân 1 cột với ma trận nghịch đảo InvMixColumns."""
    s0, s1, s2, s3 = col
    return [
        gmul(0x0E, s0) ^ gmul(0x0B, s1) ^ gmul(0x0D, s2) ^ gmul(0x09, s3),
        gmul(0x09, s0) ^ gmul(0x0E, s1) ^ gmul(0x0B, s2) ^ gmul(0x0D, s3),
        gmul(0x0D, s0) ^ gmul(0x09, s1) ^ gmul(0x0E, s2) ^ gmul(0x0B, s3),
        gmul(0x0B, s0) ^ gmul(0x0D, s1) ^ gmul(0x09, s2) ^ gmul(0x0E, s3),
    ]


def _mix_columns(state: list) -> list:
    new_state = [[0]*4 for _ in range(4)]
    for col in range(4):
        column = [state[row][col] for row in range(4)]
        mixed = _mix_single_column(column)
        for row in range(4):
            new_state[row][col] = mixed[row]
    return new_state


def _inv_mix_columns(state: list) -> list:
    new_state = [[0]*4 for _ in range(4)]
    for col in range(4):
        column = [state[row][col] for row in range(4)]
        mixed = _inv_mix_single_column(column)
        for row in range(4):
            new_state[row][col] = mixed[row]
    return new_state


# ──────────────────────────────────────────────
# Bước 4: AddRoundKey — XOR state với round key
# ──────────────────────────────────────────────

def _add_round_key(state: list, round_key: list) -> list:
    """round_key là list 4 words, mỗi word 4 bytes."""
    rk_matrix = round_key_to_matrix(round_key)
    return [[state[r][c] ^ rk_matrix[r][c] for c in range(4)] for r in range(4)]


# ──────────────────────────────────────────────
# Encrypt / Decrypt 1 block (16 bytes)
# ──────────────────────────────────────────────

def encrypt_block(block: bytes, round_keys: list) -> bytes:
    """
    Mã hóa 1 block 16 bytes với AES-128 (10 rounds).
    round_keys: output của key_expansion()
    """
    state = _bytes_to_state(block)

    # Initial round
    state = _add_round_key(state, round_keys[0])

    # Rounds 1-9
    for r in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[r])

    # Final round (no MixColumns)
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[10])

    return _state_to_bytes(state)


def decrypt_block(block: bytes, round_keys: list) -> bytes:
    """
    Giải mã 1 block 16 bytes với AES-128 (10 rounds ngược).
    """
    state = _bytes_to_state(block)

    # Initial round (dùng round key cuối)
    state = _add_round_key(state, round_keys[10])

    # Rounds 9-1 (ngược)
    for r in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[r])
        state = _inv_mix_columns(state)

    # Final round
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)


# ──────────────────────────────────────────────
# CBC Mode
# ──────────────────────────────────────────────

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Mã hóa dữ liệu bằng AES-128 CBC mode.
    - Tự động pad PKCS7
    - Trả về ciphertext (không bao gồm IV)
    """
    if len(key) != 16:
        raise ValueError("Key phải đúng 16 bytes (AES-128)")
    if len(iv) != 16:
        raise ValueError("IV phải đúng 16 bytes")

    round_keys = key_expansion(key)
    padded = pad(plaintext)
    ciphertext = b""
    prev_block = iv

    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        # XOR với block trước (CBC chaining)
        xored = bytes(block[j] ^ prev_block[j] for j in range(16))
        encrypted = encrypt_block(xored, round_keys)
        ciphertext += encrypted
        prev_block = encrypted

    return ciphertext


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Giải mã dữ liệu AES-128 CBC mode.
    - Tự động unpad PKCS7
    - Trả về plaintext gốc
    """
    if len(key) != 16:
        raise ValueError("Key phải đúng 16 bytes (AES-128)")
    if len(iv) != 16:
        raise ValueError("IV phải đúng 16 bytes")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext phải là bội số của 16 bytes")

    round_keys = key_expansion(key)
    plaintext = b""
    prev_block = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted = decrypt_block(block, round_keys)
        # XOR với block cipher trước để ra plaintext
        xored = bytes(decrypted[j] ^ prev_block[j] for j in range(16))
        plaintext += xored
        prev_block = block

    return unpad(plaintext)
