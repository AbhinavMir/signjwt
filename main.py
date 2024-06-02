from fastapi import FastAPI, HTTPException, Request, Body
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt
from jwt.exceptions import InvalidSignatureError
import sqlite3
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64
from json import JSONDecodeError


app = FastAPI()
 
DATABASE = 'app.db'
SECRET_KEY = "SECRET_KEY"
ALGORITHM = "HS256"

class User(BaseModel):
    user_id: str
    public_key: str
    
class LoginRequest(BaseModel):
    user_id: str
    
def db_connection():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
    except sqlite3.error as e:
        print(e)
    return conn

@app.on_event("startup")
def startup():
    conn = db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            public_key TEXT
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            user_id TEXT,
            expires DATETIME,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
    """)
    conn.commit()
    conn.close()

def generate_nonce(user_id):
    nonce = secrets.token_urlsafe(16)
    conn = db_connection()
    cursor = conn.cursor()
    expires = (datetime.utcnow() + timedelta(seconds=30)).strftime("%Y-%m-%d %H:%M:%S.%f")
    cursor.execute("""
        INSERT INTO nonces (nonce, user_id, expires)
        VALUES (?, ?, ?);
    """, (nonce, user_id, expires))
    conn.commit()
    conn.close()
    return nonce

def generate_jwt(user_id, nonce):
    expiration = datetime.utcnow() + timedelta(minutes=30)
    payload = {"sub": user_id, "exp": expiration, "nonce": nonce}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_jwt(token):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        nonce = decoded_token.get("nonce")
        conn = db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT expires FROM nonces WHERE nonce=?;
        """, (nonce,))
        nonce_info = cursor.fetchone()
        conn.close()
        if nonce_info is None:
            raise HTTPException(status_code=403, detail="Nonce is invalid or expired.")
        
        # Convert the string to datetime object
        nonce_expiration = datetime.strptime(nonce_info[0], "%Y-%m-%d %H:%M:%S.%f")
        
        if nonce_expiration < datetime.utcnow():
            raise HTTPException(status_code=403, detail="Nonce is invalid or expired.")
        return decoded_token["sub"]
    except InvalidSignatureError:
        raise HTTPException(status_code=403, detail="Invalid token signature.")

@app.post("/register")
def register(user: User):
    conn = db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (user_id, public_key) VALUES (?, ?);", (user.user_id, user.public_key))
    conn.commit()
    conn.close()
    return {"message": "User registered successfully with public key"}

@app.post("/login")
def login(request: LoginRequest):
    user_id = request.user_id
    conn = db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users WHERE user_id=?;", (user_id,))
    if cursor.fetchone() is None:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")
    nonce = generate_nonce(user_id)
    jwt_token = generate_jwt(user_id, nonce)
    conn.close()
    return {"jwt": jwt_token, "nonce": nonce}

def verify_signature(user_id, nonce, jwt_token, signature):
    conn = db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM users WHERE user_id = ?;", (user_id,))
    public_key_data = cursor.fetchone()
    conn.close()
    if not public_key_data:
        raise HTTPException(status_code=404, detail="User public key not found.")
    
    public_key = load_pem_public_key(public_key_data[0].encode())
    original_message = f"{nonce}{jwt_token}".encode()
    try:
        public_key.verify(
            base64.b64decode(signature),
            original_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        raise HTTPException(status_code=403, detail="Access not granted! Signature verification failed.")

@app.get("/users/{user_id}")
async def get_user(user_id: str):
    conn = db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM users WHERE user_id = ?;", (user_id,))
    public_key = cursor.fetchone()
    conn.close()
    if not public_key:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"public_key": public_key[0]}

@app.post("/protected")
async def protected(request: Request):
    data = await request.json()
    token = data.get("jwt")
    signature = data.get("signed_message")
    if not token or not signature:
        raise HTTPException(status_code=400, detail="Missing JWT or signature.")
    
    user_id = verify_jwt(token)
    
    # Retrieve the JWT token to extract the nonce
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    nonce = decoded_token.get("nonce")
    
    verify_signature(user_id, nonce, token, signature)
    
    # If verification is successful
    return {"message": "Access granted"}

@app.get("/unprotected")
async def unprotected(request: Request):
    token = request.headers.get("Authorization")
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Missing JWT.")
    
    # Extract the JWT token by removing the "Bearer " prefix
    token = token[7:]  # Adjust based on the exact length of "Bearer "
    user_id = verify_jwt(token)
    
    return {"message": "Access granted"}

@app.post("/logout")
async def logout(request: Request):
    data = await request.json()
    user_id = data.get("user_id")
    conn = db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM nonces WHERE user_id = ?;", (user_id,))
    conn.commit()
    conn.close()
    return {"message": "User logged out successfully."}