import requests
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

# API URL Configuration
API_URL = "http://localhost:8000"
REGISTER_URL = f"{API_URL}/register"
LOGIN_URL = f"{API_URL}/login"
PROTECTED_URL = f"{API_URL}/protected"

# Generate RSA keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private_key.decode(), pem_public_key.decode()

# Register User
def register_user(user_id, public_key):
    response = requests.post(REGISTER_URL, json={
        "user_id": user_id,
        "public_key": public_key
    })
    print(response.text)
    return response.status_code

# Login User
def login_user(user_id):
    # Only user_id is needed to login according to your FastAPI endpoint.
    response = requests.post(LOGIN_URL, json={"user_id": user_id})
    if response.status_code == 200:
        return response.json()
    else:
        print("Login failed:", response.text)
        return None


# Access Protected Resource
def access_protected(jwt, nonce, private_key):
    private_key_obj = serialization.load_pem_private_key(
        private_key.encode(),
        password=None,
    )
    message = f"{nonce}{jwt}".encode()
    signature = private_key_obj.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    encoded_signature = base64.b64encode(signature).decode()

    response = requests.post(PROTECTED_URL, json={
        "jwt": jwt,
        "signed_message": encoded_signature
    })
    print("Server Response from /protected:", response.text)

def access_unprotected(jwt):
    UNPROTECTED_URL = f"{API_URL}/unprotected"
    headers = {"Authorization": f"Bearer {jwt}"}
    response = requests.get(UNPROTECTED_URL, headers=headers)
    print("Server Response from /unprotected:", response.text)

    
def user_exists(user_id):
    response = requests.get(f"{API_URL}/users/{user_id}")
    return response.status_code == 200

def logout_user(user_id):
    response = requests.post(f"{API_URL}/logout", json={"user_id": user_id})
    print("Server Response from /logout:", response.text)
    return response.status_code

def main():
    user_id = "testuser1"
    if not user_exists(user_id):
        private_key, public_key = generate_keys()
        # save private key to .keys for user
        with open(f"keys/{user_id}.keys", "wb") as f:
            f.write(private_key.encode())
        print("Generated RSA keys for user:", user_id)

        # Register user
        if register_user(user_id, public_key) != 200:
            print("User registration failed.")
            return
    else:
        print("User already exists.")
        private_key = open(f"keys/{user_id}.keys", "rb").read().decode()

    # Login and get JWT and nonce
    login_data = login_user(user_id)
    if not login_data:
        print("Login failed.")
        return

    print("Logged in successfully:", login_data)
    jwt = login_data.get("jwt")
    print("JWT:", jwt)
    nonce = login_data.get("nonce")
    print("Nonce:", nonce)

    # Access protected resource
    access_protected(jwt, nonce, private_key)
    access_unprotected(jwt)
    
    # try to access protected after a user has logged out
    baduser_id = "baduser"
    if not user_exists(baduser_id):
        print(f"User {baduser_id} does not exist.")
        baduser_private_key, baduser_public_key = generate_keys()
        if register_user(baduser_id, baduser_public_key) != 200:
            print("User registration failed.")
            return
    else:
        print(f"User {baduser_id} exists.")

    # Test /protected endpoint with correct JWT and previous_user's private key
    baduser_login_data = login_user(baduser_id)
    if baduser_login_data:
        baduser_jwt = baduser_login_data.get("jwt")
        baduser_nonce = baduser_login_data.get("nonce")

        access_protected(baduser_jwt, baduser_nonce, private_key)
        access_unprotected(baduser_jwt)



if __name__ == "__main__":
    main()
