# 🛡️ SecureChat: End-to-End Encrypted Messaging System

> A military-grade secure communication platform implementing Hybrid Cryptography, Forward Secrecy, and Zero-Knowledge Architecture.

**Course:** Information Security (BSSE)  
**Stack:** MERN (MongoDB, Express, React, Node.js) + Web Crypto API

---

## 🚀 Project Overview
SecureChat is a web-based messaging application designed to guarantee privacy. Unlike standard chat apps where the server holds the keys, SecureChat implements true **End-to-End Encryption (E2EE)**. Encryption and decryption occur strictly on the client device; the server acts only as a blind relay.

### 🌟 Key Security Features (Exceeds Expectations)
* **Hybrid Cryptography:** Combines **ECDH (P-256)** for speed and **RSA-2048** for identity verification.
* **AES-256-GCM:** Authenticated encryption for all messages and files (protects against tampering).
* **HKDF Key Derivation:** Derives cryptographically strong session keys using SHA-256 (standard compliant).
* **MITM Defense:** All handshakes are digitally signed. The system detects and blocks signature mismatches.
* **Replay Protection:** Encrypted payloads include monotonic Sequence Numbers and Timestamps to prevent replay attacks.
* **Two-Factor Authentication (2FA):** Registration generates a unique "Security Code" required for all future logins.
* **Secure File Sharing:** Large files are split into **64KB chunks**, encrypted individually, and reassembled on the client.
* **Persistence:** Securely stores keys in **IndexedDB** (via LocalForage) to maintain sessions across reloads.

---

## 🛠️ Technical Architecture

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Frontend** | React.js + Vite | UI and Application Logic |
| **Cryptography** | Web Crypto API | Native browser API (SubtleCrypto) for raw performance |
| **Storage** | IndexedDB (LocalForage) | Secure client-side storage for Private Keys & History |
| **Backend** | Node.js + Express | API and WebSocket Relay |
| **Real-time** | Socket.io | Bidirectional event-based communication |
| **Database** | MongoDB | Stores Users, Hashed Passwords (Bcrypt), and Public Keys |

---

## 📦 Installation & Setup

### 1. Prerequisites
* Node.js (v16 or higher)
* MongoDB (Running locally on port `27017`)

### 2. Clone and Install
```bash
# Clone the repository
git clone <repository-url>

# Install Server Dependencies
cd server
npm install

# Install Client Dependencies
cd ../client
npm install
````

### 3\. Run the System

You need two terminals open.

**Terminal 1 (Backend):**

```bash
cd server
node index.js
# Server will start on http://localhost:3001
# Audit logs will be written to server/audit_log.json
```

**Terminal 2 (Frontend):**

```bash
cd client
npm run dev
# App will launch at http://localhost:5173
```

-----

## 🧪 How to Test Security Features

### 1\. Registration & 2FA

1.  Register a new user (e.g., `Alice`).
2.  **Copy the 6-Digit Security Code** displayed on the green screen.
3.  Try to login with a wrong code (Access Denied).
4.  Login with the correct code to enter the Secure Vault.

### 2\. The Secure Handshake

1.  Open two browsers (Alice and Bob).
2.  Alice clicks "Bob" in the contact list.
3.  Bob clicks **"Verify & Accept"**.
4.  Observe the **"Green Lock"** icon indicating `HKDF+AES` keys are established.

### 3\. Attack Simulation (Built-in Tools)

We have included "Red Team" tools directly in the UI for demonstration purposes.

  * **MITM Attack:**

    1.  Click the **Yellow "MITM" Button** (Spy Icon).
    2.  This injects a handshake offer with a **Fake Key** and **Invalid Signature**.
    3.  **Result:** Victim sees `❌ SECURITY ALERT: Signature Mismatch`.

  * **Replay Attack:**

    1.  Send a valid message "Hello".
    2.  Click the **Red "Attack" Button** (Lightning Icon).
    3.  This captures the last encrypted packet and resends it with an old Sequence Number.
    4.  **Result:** Victim console logs `REPLAY ATTACK DETECTED` and drops the packet.

-----

## 📂 Project Structure

```
/client
  /src
    /components
      Auth.jsx       # 2FA Login & Key Generation
      Chat.jsx       # Messaging, Chunking, Attack Demos
    /utils
      cryptoUtils.js # The Core Cryptographic Engine (Web Crypto API)
/server
  index.js           # Socket Relay & API
  logger.js          # Security Auditing
  audit_log.json     # Immutable Event Log
```

## ⚠️ Disclaimer

This project is for educational purposes. It implements a custom cryptographic protocol. While it adheres to modern standards (NIST curves, AES-GCM), it has not been audited by a third party.

```