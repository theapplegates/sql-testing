# Post-Quantum PGP Tool

A full-stack web application for experimenting with **Post-Quantum Cryptography (PQC)** using rPGP with **SLH-DSA signatures**.

## 🌟 Features

- **RFC9580 v6 OpenPGP Keys** - Latest OpenPGP standard
- **SLH-DSA-SHAKE-512s Signatures** - Post-quantum digital signatures
- **X25519 Encryption** - Modern elliptic curve encryption
- **Ed25519 Primary Keys** - For certification
- **Full Web Interface** - Easy-to-use React frontend
- **RESTful API** - FastAPI backend with complete OpenPGP operations

## 🚀 Quick Start

### 1. Build and Export Docker Images (First Time Only)

```bash
./export-images.sh
```

This will:
- Build the backend (Python FastAPI + Rust PGP tools)
- Build the frontend (React application)
- Export both as .tar files for quick loading

### 2. Launch the Application

```bash
./quantum
```

This loads the pre-built images and starts both services.

### 3. Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000/docs (Swagger UI)

## 🔧 Development Mode

For hot-reload development with volume mounts:

```bash
./pq
```

This mounts your local code directories:
- `./backend` → Backend container
- `./frontend` → Frontend container

Changes to your code will be reflected immediately without rebuilding.

## 🛑 Reset Environment

To stop containers and remove images:

```bash
./reset
```

## 📖 Usage Guide

### Generate a Key

1. Navigate to the "Generate Key" tab
2. Enter your User ID (e.g., "John Doe <john@example.com>")
3. Optionally set a password
4. Click "Generate Key"
5. Download your secret and public keys as `.asc` files

**Key Details:**
- Primary Key: Ed25519 (v6) - for certification
- Signing Subkey: SLH-DSA-SHAKE-256s (v6) - Post-quantum signatures
- Encryption Subkey: X25519 (v6) - for encryption

### Sign a Message

1. Navigate to the "Sign" tab
2. Paste your secret key
3. Enter your password (if key is encrypted)
4. Type your message
5. Click "Sign Message"
6. Download the signed message as `.asc`

### Verify a Signature

1. Navigate to the "Verify" tab
2. Paste the public key
3. Paste the signed message
4. Click "Verify Signature"
5. View verification result and extracted message

### Encrypt a Message

1. Navigate to the "Encrypt" tab
2. Paste the recipient's public key
3. Type your message
4. Click "Encrypt Message"
5. Download the encrypted message as `.asc`

### Decrypt a Message

1. Navigate to the "Decrypt" tab
2. Paste your secret key
3. Enter your password (if key is encrypted)
4. Paste the encrypted message
5. Click "Decrypt Message"
6. View the decrypted plaintext

## 🏗️ Architecture

### Backend (`/backend`)

Python FastAPI service that orchestrates Rust PGP operations:
- `main.py` - FastAPI application with REST endpoints
- `bin/` - Compiled Rust PGP tools
  - `pgp-keygen` - Generate v6 keys
  - `pgp-sign` - Sign messages
  - `pgp-verify` - Verify signatures
  - `pgp-encrypt` - Encrypt messages
  - `pgp-decrypt` - Decrypt messages

### Frontend (`/frontend`)

React application with modern UI:
- Single-page application
- Tabbed interface for all operations
- File download capabilities
- Real-time error handling

### rPGP Library (`/rpgp`)

Modified rPGP Rust library:
- Forked from https://github.com/rpgp/rpgp
- Feature flag: `draft-pqc` (enables Post-Quantum algorithms)
- Implements draft-ietf-openpgp-pqc-12

### Rust Tools (`/rpgp-tools`)

Standalone CLI binaries that wrap the rPGP library:
- Built with `--release` flag for performance
- All tools export/import `.asc` (ASCII armored) files
- Command-line interface for automation

## 🔐 Cryptographic Details

### Key Structure (v6)

```
Primary Key (Ed25519)
├── User ID
├── Signing Subkey (SLH-DSA-SHAKE-128s) ← Post-Quantum!
└── Encryption Subkey (X25519)
```

### Algorithms Used

- **Signatures**: SLH-DSA-SHAKE-256s (Post-Quantum)
- **Encryption**: X25519 with AES256
- **Hash**: SH3-512 for signatures
- **AEAD**: SEIPD v1 with AES256

### Key Format

All keys are exported as **ASCII Armored** (`.asc`) files:
- `-----BEGIN PGP PRIVATE KEY BLOCK-----`
- `-----BEGIN PGP PUBLIC KEY BLOCK-----`
- `-----BEGIN PGP MESSAGE-----`
- `-----BEGIN PGP SIGNATURE-----`

## 📦 Project Structure

```
pgp-tool-final/
├── backend/               # FastAPI backend
│   ├── bin/              # Rust PGP tool binaries
│   ├── main.py           # FastAPI application
│   └── Dockerfile
├── frontend/             # React frontend
│   ├── src/
│   │   ├── App.js       # Main application
│   │   ├── App.css      # Styling
│   │   └── index.js     # Entry point
│   ├── public/
│   └── Dockerfile
├── rpgp/                 # rPGP Rust library (modified)
├── rpgp-tools/           # Rust CLI tools (source)
│   └── src/
│       ├── keygen.rs
│       ├── sign.rs
│       ├── verify.rs
│       ├── encrypt.rs
│       └── decrypt.rs
├── docker-compose.yml    # Production compose
├── docker-compose.override.yml  # Development volumes
├── quantum               # Launch script (production)
├── pq                    # Launch script (development)
├── reset                 # Cleanup script
├── export-images.sh      # Build and export images
└── README.md
```

## ⚠️ Security Notice

**THIS IS AN EXPERIMENTAL IMPLEMENTATION**

- Uses `draft-pqc` feature (draft-ietf-openpgp-pqc-12)
- **DO NOT USE IN PRODUCTION**
- For research and experimentation only
- Post-quantum algorithms are still being standardized

## 🧪 API Documentation

Once running, visit http://localhost:8000/docs for interactive API documentation (Swagger UI).

### Endpoints

- `POST /generate-key` - Generate new v6 key pair
- `POST /sign` - Sign a message
- `POST /verify` - Verify a signature
- `POST /encrypt` - Encrypt a message
- `POST /decrypt` - Decrypt a message
- `GET /health` - Health check
- `GET /` - API information

## 🛠️ Development

### Building Rust Tools

```bash
cd rpgp-tools
cargo build --release
```

Binaries will be in `target/release/`.

### Running Backend Locally

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Running Frontend Locally

```bash
cd frontend
npm install
npm start
```

## 📚 References

- [RFC 9580 - OpenPGP](https://www.rfc-editor.org/rfc/rfc9580.html)
- [rPGP Library](https://github.com/rpgp/rpgp)
- [SLH-DSA Specification](https://csrc.nist.gov/pubs/fips/205/ipd)
- [Draft OpenPGP PQC](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/)

## 📝 License

This project uses rPGP which is licensed under MIT OR Apache-2.0.

## 🤝 Contributing

This is an experimental project. Feel free to explore, experiment, and learn!

---

**Built with** Rust 🦀 • Python 🐍 • React ⚛️ • Docker 🐳
