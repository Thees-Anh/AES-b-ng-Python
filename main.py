import os
from network.sender import send_file
from network.receiver import receive_file

KEY = b"MySuperSecretKey"   # 16 bytes


def menu():
    print("\n====== AES FILE TRANSFER ======")
    print("1. Send File")
    print("2. Receive File")
    print("3. Exit")


def main():
    while True:
        menu()
        choice = input("Select option: ")

        if choice == "1":
            # SEND
            host = input("Enter receiver IP: ")
            port = int(input("Enter port: "))
            file_path = input("Enter file path: ")

            if not os.path.exists(file_path):
                print("[ERROR] File not found!")
                continue

            send_file(host, port, file_path, KEY)

        elif choice == "2":
            # RECEIVE
            host = "0.0.0.0"   # lắng nghe tất cả IP
            port = int(input("Enter port to listen: "))
            output_dir = "received_files"

            os.makedirs(output_dir, exist_ok=True)

            receive_file(host, port, KEY, output_dir)

        elif choice == "3":
            print("Exit.")
            break

        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()