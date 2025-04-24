import socket
import threading
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad, pad
import hashlib
from Crypto.Random import get_random_bytes

clients = {}

def sha256_hash(data):
    return hashlib.sha256(data).hexdigest()

def handle_client(client_socket, address, rsa_cipher):
    print(f"[+] New client connected: {address}")
    

    try:
        encrypted_key = client_socket.recv(256)
        aes_key = rsa_cipher.decrypt(encrypted_key)
        clients[client_socket] = aes_key
        print(f"[🔑] AES key successfully received and decrypted from {address}")
    except Exception as e:
        print(f"[!] Failed to exchange AES key with {address}: {e}")
        client_socket.close()
        return

    def receive_messages():
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break

                iv = data[:16]
                ciphertext = data[16:-64]
                msg_hash = data[-64:].decode()

                print(f"\n[🔐 Received from {address}]")
                print(f"IV (hex): {iv.hex()}")
                print(f"Ciphertext (hex): {ciphertext.hex()}")
                print(f"Received SHA-256 hash: {msg_hash}")

                cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
                message = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

                calculated_hash = sha256_hash(message)
                print(f"Decrypted message: {message.decode()}")
                print(f"Calculated SHA-256 hash: {calculated_hash}")

                if calculated_hash != msg_hash:
                    print(f"[❌] Hash mismatch! Message may have been tampered.")
                    continue
                else:
                    print(f"[✅] Message integrity verified.")

                print(f"[{address}] {message.decode()}")

            except Exception as e:
                print(f"[!] Error with client {address}: {e}")
                break

        print(f"[-] Client disconnected: {address}")
        client_socket.close()
        del clients[client_socket]

    threading.Thread(target=receive_messages, daemon=True).start()

def start_server():
    # Load private key
    with open("private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    rsa_cipher = PKCS1_OAEP.new(private_key)

    server = socket.socket()
    server.bind(('localhost', 12000))
    server.listen(5)
    print("🔐 Secure Chat Server started on port 12000...")

    threading.Thread(target=send_messages_to_clients, daemon=True).start()

    while True:
        client_socket, address = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, address, rsa_cipher)).start()

def send_messages_to_clients():
    while True:
        msg = input("🖊️ Server: ").strip().encode()
        if not msg:
            continue
        for client_socket, aes_key in list(clients.items()):
            try:
                iv = get_random_bytes(16)
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                ciphertext = cipher.encrypt(pad(msg, AES.block_size))
                msg_hash = sha256_hash(msg).encode()

                print(f"\n[✉️ Sending to {client_socket.getpeername()}]")
                print(f"Plaintext message: {msg.decode()}")
                print(f"IV (hex): {iv.hex()}")
                print(f"Ciphertext (hex): {ciphertext.hex()}")
                print(f"SHA-256 hash: {msg_hash.decode()}")

                client_socket.send(iv + ciphertext + msg_hash)
            except Exception as e:
                print(f"[!] Failed to send to {client_socket.getpeername()}: {e}")

start_server()
