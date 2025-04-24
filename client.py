import socket
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

def sha256_hash(data):
    return hashlib.sha256(data).hexdigest()


with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())
rsa_cipher = PKCS1_OAEP.new(public_key)

client = socket.socket()
client.connect(('localhost', 12000))
print("🔐 Connected to Secure Chat Server.")


aes_key = get_random_bytes(16)
encrypted_key = rsa_cipher.encrypt(aes_key)
client.send(encrypted_key)
print("[🔑] AES key generated and securely sent to server.")

def receive_messages():
    while True:
        try:
            data = client.recv(4096)
            if not data:
                break

            iv = data[:16]
            ciphertext = data[16:-64]
            msg_hash = data[-64:].decode()

            print(f"\n[📥 Incoming from Server]")
            print(f"IV (hex): {iv.hex()}")
            print(f"Ciphertext (hex): {ciphertext.hex()}")
            print(f"Received SHA-256 hash: {msg_hash}")

            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            msg = unpad(cipher.decrypt(ciphertext), AES.block_size)

            calculated_hash = sha256_hash(msg)
            print(f"Decrypted message: {msg.decode()}")
            print(f"Calculated SHA-256 hash: {calculated_hash}")

            if calculated_hash != msg_hash:
                print("[❌] Hash mismatch! Possible tampering.")
                continue
            else:
                print("[✅] Message integrity verified.")

            print(f"\n🔓 Server: {msg.decode()}\n> ", end="")

        except Exception as e:
            print(f"[!] Receive error: {e}")
            break


threading.Thread(target=receive_messages, daemon=True).start()


while True:
    msg = input("> ").strip().encode()
    if not msg:
        continue
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(msg, AES.block_size))
    msg_hash = sha256_hash(msg).encode()

    print(f"\n[✉️ Sending to Server]")
    print(f"Plaintext message: {msg.decode()}")
    print(f"IV (hex): {iv.hex()}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"SHA-256 hash: {msg_hash.decode()}")

    client.send(iv + ciphertext + msg_hash)
