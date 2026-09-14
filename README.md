# Basic JWKS Server

A RESTful JWKS server for CSCE 3550.

## Features

- RSA key pair generation
- Unique `kid` values
- JWT creation using RS256
- JWKS endpoint for public key verification
- Expired key and expired JWT support
- Automated tests with over 80% coverage

## Endpoints

### POST /auth

Returns a signed JWT.

Example:

```bash
curl -X POST http://localhost:8080/auth

