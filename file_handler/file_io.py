# file_handler/file_io.py

def read_file(file_path: str) -> bytes:
    """
    Đọc file dưới dạng bytes
    """
    try:
        with open(file_path, "rb") as f:
            data: bytes = f.read()
        return data
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return b""


def write_file(file_path: str, data: bytes) -> None:
    """
    Ghi dữ liệu bytes ra file
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes")

    try:
        with open(file_path, "wb") as f:
            f.write(data)
        print(f"[+] File saved: {file_path}")
    except Exception as e:
        print(f"[ERROR] Cannot write file: {e}")