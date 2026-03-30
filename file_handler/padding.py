# file_handler/padding.py

BLOCK_SIZE: int = 16


def pad(data: bytes) -> bytes:
    """
    Thêm padding theo chuẩn PKCS7
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes")

    padding_len: int = BLOCK_SIZE - (len(data) % BLOCK_SIZE)

    # tạo padding dạng bytes
    padding: bytes = bytes([padding_len] * padding_len)

    return data + padding


def unpad(data: bytes) -> bytes:
    """
    Loại bỏ padding PKCS7
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes")

    if len(data) == 0:
        raise ValueError("Data is empty")

    # lấy giá trị padding cuối
    padding_len: int = int(data[-1])   # 👈 fix lỗi IDE ở đây

    # kiểm tra padding hợp lệ
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")

    # kiểm tra toàn bộ byte padding
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding")

    return data[:-padding_len]