# network/sender.py
# Máy GỬI: đọc file -> mã hóa AES-128 CBC -> gửi qua TCP socket

import socket
import os
import argparse
from ase_core.aes import aes_cbc_encrypt
from file_handler.file_io import read_file

# Giao thức truyền file:
# [4 bytes] độ dài tên file (big-endian uint32)
# [N bytes] tên file (UTF-8)
# [4 bytes] độ dài ciphertext
# [16 bytes] IV
# [M bytes] ciphertext


def send_file(host: str, port: int, file_path: str, key: bytes):
    """
    Mã hóa file và gửi tới receiver qua TCP.
    host     : địa chỉ IP máy nhận
    port     : cổng TCP
    file_path: đường dẫn file cần gửi
    key      : khóa AES 16 bytes
    """
    # Đọc file
    data = read_file(file_path)
    if data is None:
        print(f"[!] Không đọc được file: {file_path}")
        return

    filename = os.path.basename(file_path).encode("utf-8")

    # Sinh IV ngẫu nhiên
    iv = os.urandom(16)

    # Mã hóa
    print(f"[*] Đang mã hóa {file_path} ({len(data)} bytes)...")
    ciphertext = aes_cbc_encrypt(data, key, iv)
    print(f"[+] Mã hóa xong — ciphertext: {len(ciphertext)} bytes")

    # Xây dựng payload
    filename_len  = len(filename).to_bytes(4, "big")
    cipher_len    = len(ciphertext).to_bytes(4, "big")

    payload = filename_len + filename + cipher_len + iv + ciphertext

    # Gửi qua TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[*] Đang kết nối tới {host}:{port}...")
        s.connect((host, port))
        s.sendall(payload)
        print(f"[+] Đã gửi {len(payload)} bytes tổng cộng")

    print("[+] Hoàn thành!")


def main():
    parser = argparse.ArgumentParser(description="AES File Sender")
    parser.add_argument("--host", default="127.0.0.1", help="IP máy nhận (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Cổng TCP (default: 9999)")
    parser.add_argument("--file", required=True, help="Đường dẫn file cần gửi")
    parser.add_argument("--key", required=True, help="Khóa AES (đúng 16 ký tự)")
    args = parser.parse_args()

    key = args.key.encode("utf-8")
    if len(key) != 16:
        print(f"[!] Khóa phải đúng 16 bytes, hiện có {len(key)} bytes")
        return

    send_file(args.host, args.port, args.file, key)


if __name__ == "__main__":
    main()
