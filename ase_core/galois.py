# ase_core/galois.py
# Arithmetic in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)

IRREDUCIBLE_POLY = 0x11B


def xtime(a: int) -> int:
    """
    Nhân một byte với x (tức nhân với 2) trong GF(2^8).
    Nếu bit cao (bit 7) = 1, sau khi shift trái thì XOR với 0x1B (phần thấp của 0x11B).
    """
    result = (a << 1) & 0xFF
    if a & 0x80:
        result ^= 0x1B
    return result


def gmul(a: int, b: int) -> int:
    """
    Nhân hai byte trong GF(2^8) bằng phương pháp 'peasant multiplication'.
    Không dùng bảng tra cứu, tính thuần túy bằng bit.

    Ví dụ chuẩn NIST: gmul(0x57, 0x83) == 0xC1
    """
    result = 0
    a = a & 0xFF
    b = b & 0xFF
    for _ in range(8):
        if b & 1:          # nếu bit thấp nhất của b là 1, cộng a vào result
            result ^= a
        a = xtime(a)       # nhân a với x
        b >>= 1            # shift b sang phải
    return result


def gadd(a: int, b: int) -> int:
    """
    Cộng hai byte trong GF(2^8) — đơn giản là XOR.
    """
    return a ^ b


def ginv(a: int) -> int:
    """
    Tính nghịch đảo nhân của a trong GF(2^8).
    Dùng thuật toán Fermat nhỏ: a^(-1) = a^(2^8 - 2) mod poly.
    ginv(0) = 0 theo chuẩn AES.
    """
    if a == 0:
        return 0
    result = 1
    exp = 254  # 2^8 - 2
    base = a
    while exp > 0:
        if exp & 1:
            result = gmul(result, base)
        base = gmul(base, base)
        exp >>= 1
    return result
