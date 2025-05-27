from flask import Flask, request, jsonify
import os
import datetime
import jwt
import bcrypt
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['JWT_SECRET'] = os.getenv("JWT_SECRET")

users = {}

def create_token(username):
    payload= {
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')
    return token

def decode_token(token):
    try:
        decoded = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username in users:
        return jsonify({"error": "User already exists"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = hashed_password

    return jsonify({"message": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_password = users.get(username)
    if not hashed_password or not bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(username)
    return jsonify({"token": token}), 200

@app.route('/me', methods=['GET'])
def me():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header missing or invalid"}), 401
    token = auth_header.split(" ")[1]
    decoded = decode_token(token)
    if not decoded:
        return jsonify({"error": "Invalid or expired token"}), 401

    return jsonify({"username": decoded['username']}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5010)

