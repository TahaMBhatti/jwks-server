A JWKS server that will generate RSA keys, signs JWTs and stores private keys safely in SQLite

Requirements:
Python 3.9 or newer
pip



Installation: 
	clone the repository: 
	git clone https://github.com/TahaMBhatti/jwks-server.git
	cd jwks-server

	Create and ancticate a virtual environment:
	python3 -m venv venv
        source venv/bin/activate

	Install dependencies:
	pip install -r requirements.txt

Running the server:
	Start flask app:
	python app.py
	(server runs at http://127.0.0.1:8080)

POST /auth
Issue a signed JWT using valid RSA priv key:
curl -X POST http://127.0.0.1:8080/auth

request expired JWT:
curl -X POST "http://127.0.0.1:8080/auth?expired=true" 


Testing:
automated test suite:
python -m pytest -v
	last verified results were:
	5 automated test passed
	84% code coverage
