# Basic JWKS Server

A RESTful JWKS server for CSCE 3550.

## Features

- RSA key pair generation
- Unique `kid` values
- JWT creation using RS256
- JWKS endpoint for public key verification
- Expired key and expired JWT support
- Automated tests with over 80% coverage

## Requirements

- Python 3
- pip

## Setup

Clone the repository:

```bash
git clone https://github.com/TahaMBhatti/jwks-server.git
cd jwks-server

Create a virtual environment:

python3 -m venv venv


Activate the virtual environment:

source venv/bin/activate


Install dependencies:

pip install -r requirements.txt


Run the server:

python app.py
