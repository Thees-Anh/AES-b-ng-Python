# network/receiver.py
# Máy NHẬN: lắng nghe TCP -> nhận dữ liệu -> giải mã AES-128 CBC -> lưu file

import socket
import os
import argparse
from ase_core.aes import aes_cbc_decrypt
from file_handler.file_io import write_file

# Giao thức nhận (đối xứng với sender):
# [4 bytes] độ dài tên file
# [N bytes] tên file (UTF-8)
# [4 bytes] độ dài ciphertext
# [16 bytes] IV
# [M bytes] ciphertext


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    """Nhận đúng n bytes từ socket (loop cho đến khi đủ)."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Kết nối bị đóng trước khi nhận đủ dữ liệu")
        buf += chunk
    return buf


def receive_file(host: str, port: int, key: bytes, output_dir: str = "."):
    """
    Lắng nghe TCP, nhận 1 file mã hóa, giải mã và lưu ra output_dir.
    """
    os.makedirs(output_dir, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        print(f"[*] Đang lắng nghe tại {host}:{port} ...")

        conn, addr = server.accept()
        print(f"[+] Kết nối từ {addr}")

        with conn:
            # Đọc tên file
            filename_len = int.from_bytes(_recv_exact(conn, 4), "big")
            filename     = _recv_exact(conn, filename_len).decode("utf-8")
            print(f"[*] Tên file: {filename}")

            # Đọc độ dài ciphertext + IV + ciphertext
            cipher_len   = int.from_bytes(_recv_exact(conn, 4), "big")
            iv           = _recv_exact(conn, 16)
            ciphertext   = _recv_exact(conn, cipher_len)
            print(f"[*] Nhận {cipher_len} bytes ciphertext")

            # Giải mã
            print("[*] Đang giải mã...")
            plaintext = aes_cbc_decrypt(ciphertext, key, iv)
            print(f"[+] Giải mã xong — {len(plaintext)} bytes")

            # Lưu file
            out_path = os.path.join(output_dir, "decrypted_" + filename)
            write_file(out_path, plaintext)
            print(f"[+] Đã lưu ra: {out_path}")


def main():
    parser = argparse.ArgumentParser(description="AES File Receiver")
    parser.add_argument("--host",   default="0.0.0.0", help="IP lắng nghe (default: 0.0.0.0)")
    parser.add_argument("--port",   type=int, default=9999, help="Cổng TCP (default: 9999)")
    parser.add_argument("--key",    required=True, help="Khóa AES (đúng 16 ký tự)")
    parser.add_argument("--output", default=".",  help="Thư mục lưu file đầu ra")
    args = parser.parse_args()

    key = args.key.encode("utf-8")
    if len(key) != 16:
        print(f"[!] Khóa phải đúng 16 bytes, hiện có {len(key)} bytes")
        return

    receive_file(args.host, args.port, key, args.output)


if __name__ == "__main__":
    main()
