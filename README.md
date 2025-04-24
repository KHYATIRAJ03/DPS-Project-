# 🔐 Secure Chat Application (RSA + AES Encrypted)

This is a secure client-server chat system built in Python using **RSA** and **AES** encryption to protect communications. It ensures message confidentiality and integrity using **SHA-256 hashing** and hybrid cryptography.

---

## 📁 Files

| File             | Description                                 |
|------------------|---------------------------------------------|
| `client.py`      | Client-side script to connect & send messages |
| `server.py`      | Server-side script to handle multiple clients |
| `generate_key.py`| Script to generate RSA key pair              |
| `public.pem`     | RSA public key (used by clients)             |
| `private.pem`    | RSA private key (used by server)             |

---

## 🔧 Features

- 🔐 **RSA-2048** encryption for AES key exchange
- 🛡️ **AES-CBC** (128-bit) encryption for messages
- 📎 **SHA-256 hashing** for integrity check
- 🔄 Multithreaded server to handle multiple clients simultaneously
- 🔁 Bi-directional secure communication between server and clients

---

## 🚀 Getting Started

### 1. Install Dependencies

Install the required library:

```bash
pip install pycryptodome
2. Generate Keys
Before starting, generate your RSA key pair:

bash
Copy
Edit
python generate_key.py
This creates:

private.pem (for the server)

public.pem (for the clients)

3. Start the Server
bash
Copy
Edit
python server.py
4. Start a Client (in a new terminal)
bash
Copy
Edit
python client.py
You can launch multiple clients to simulate a chat room.

💬 How It Works
🔑 Key Exchange
Client reads public.pem and encrypts a random 128-bit AES key.

Server decrypts it using private.pem.

✉️ Message Flow
Client or server encrypts message with AES in CBC mode using:

A new random IV

SHA-256 hash of plaintext message

Receiver decrypts the message, verifies integrity using the hash.

📸 Sample Output
Client:
bash
Copy
Edit
🔐 Connected to Secure Chat Server.
[🔑] AES key generated and securely sent to server.
> Hello Server!
Server:
bash
Copy
Edit
[+] New client connected: ('127.0.0.1', 54321)
[🔑] AES key successfully received and decrypted
[✅] Message integrity verified.
[('127.0.0.1', 54321)] Hello Server!
⚠️ Security Notes
Keep private.pem secure and never share it.

Distribute only public.pem to trusted clients.

Messages with hash mismatches are ignored to prevent tampering.

🛠️ Future Ideas
Add authentication layer

GUI using Tkinter or PyQt

Encrypted file sharing

WebSocket support for real-time web app integration

📄 License
This project is open-source under the MIT License.
