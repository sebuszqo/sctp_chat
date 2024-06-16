import uuid
import json
from base64 import b64decode
from Crypto.Cipher import AES
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket
import json
import struct
from pydantic import BaseModel, ValidationError, field_validator
from enum import Enum
import base64
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import Crypto.Random
import hashlib
import time
import base64


PASSWORD = b"pass"
SALTLEN = 8
KEYLEN = 32
IVLEN = 16
ITERATIONS = 10002
ENCRYPT = 1
DECRYPT = 0

class Command(Enum):
    Start = 0
    Stop = 1
    Restart = 2
    Status = 3
    Login = 4

class ServerConnection(BaseModel):
    IP: str
    Port: str

    def full_address(self) -> str:
        return f"{self.IP}:{self.Port}"
    

class ServerInfo(BaseModel):
    Name: str
    GameType: str
    TCPConn: ServerConnection
    PublicKey: str
    Command: str

    @field_validator('PublicKey')
    def check_public_key(cls, v):
        if not v.startswith("-----BEGIN RSA PUBLIC KEY-----"):
            raise ValueError("Invalid public key format")
        return v
    
    def get_IP(self) -> str:
        return self.TCPConn.IP
    
    def get_Port(self) -> str:
        return self.TCPConn.Port
    

class TCP_Client:
    def __init__(self, server_ip: str , server_port: int):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logged = False
        self.aes_key = self.generate_aes_key()
        try:
            self.client_socket.connect((self.server_ip, self.server_port))
        except socket.error as e:
            print(f"Failed to connect to {self.server_ip}:{self.server_port}. Error: {e}")
            raise
    
    def generate_aes_key(self):
        key = get_random_bytes(32)  # Generowanie 16-bajtowego klucza AES (AES-128)
        return key
    
    def sendMsg(self, message: str):
        try:
            self.client_socket.send(message)
            return not None
        except socket.error as e:
            print(f"Failed to send message. Error: {e}")
            return None

    def recvMsg(self, buffer_size=1024):
        try:
            message = self.client_socket.recv(buffer_size)
            return message.decode('utf-8')
        except socket.error as e:
            print(f"Failed to receive message. Error: {e}")
            return None
    
    # def decrypt_aes(self, encrypted_message, aes_key):
    #     decoded = base64.b64decode(encrypted_message)
    #     nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
    #     cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    #     plaintext = cipher_aes.decrypt(cipher_aes)
    #     return plaintext.decode('utf-8')
            
    def encrypt_message(self, message, public_key_pem):
        # message = base64.encode(message, message)
        message = bytes(message, 'utf-8')
        print("DLUGOSC",len( message))
        key = RSA.importKey(public_key_pem)
        cipher = PKCS1_OAEP.new(key, SHA512)
        ciphertext = cipher.encrypt(message)
        # key = RSA.importKey(open('private.pem').read())
        # cipher = PKCS1_OAEP.new(key)
        # message = cipher.decrypt(ciphertext)
        # print("MESSAGE",message)
        # encrypted_message_b64 = base64.b64encode(encrypted_message)
        # print(f"Encrypted message (Base64): {encrypted_message_b64.decode('utf-8')}")  # Logowanie zaszyfrowanej wiadomości
        return base64.b64encode(ciphertext).decode('utf-8')

    def send_encrypted_message(self, message, public_key_pem):
        encrypted_message = self.encrypt_message(json.dumps(message), public_key_pem)
        # // dodałem kodowanie
        encoded_message = base64.b64encode(encrypted_message)
        # print(f"Sending encrypted message: {encrypted_message.decode('utf-8')}")  # Logowanie przed wysłaniem
        self.sendMsg(encoded_message)
    
    def close(self):
        if self.client_socket:
            self.client_socket.close()
    
    def generate_challenge(self):
        return get_random_bytes(16)     
    
    def send_aes(self, data :str, command):
        cipher = AES.new(self.aes_key, AES.MODE_CTR)
        ct_bytes = cipher.encrypt(data.encode('utf-8'))
        nonce = base64.b64encode(cipher.nonce).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        result = json.dumps(
            {
                'command': f"{command}", 
                'nonce': nonce, 
                'cipher_text': ct
             }
            )
        encoded_message = base64.b64encode(result.encode('utf-8'))
        self.sendMsg(encoded_message)

    def recv_aes(self) -> str:
        base64Message = self.recvMsg(1024)
        try:
            decoded_message = base64.b64decode(base64Message)
            b64 = json.loads(decoded_message)
            nonce = base64.b64decode(b64['nonce'])
            ct = base64.b64decode(b64['cipher_text'])
            cipher = AES.new(self.aes_key, AES.MODE_CTR, nonce=nonce)
            pt = cipher.decrypt(ct)
            # print("The message was:", pt.decode('utf-8'))
            return pt.decode('utf-8')
        except (ValueError, KeyError) as e:
            print("Incorrect decryption", e)
    
    def challange(self, publicKey):
        print("AES KEY," ,base64.b64encode(self.aes_key).decode('utf-8'))
        encrypted_message = self.encrypt_message(base64.b64encode(self.aes_key).decode('utf-8'), publicKey)
        # // dodałem kodowanie
        message = {
            'command': 'exchange',
            'aes_key': encrypted_message,
        }
        encoded_message = base64.b64encode(json.dumps(message).encode('utf-8'))
        # print(f"Sending encrypted message: {encrypted_message.decode('utf-8')}")  # Logowanie przed wysłaniem
        self.sendMsg(encoded_message)    
    
    def register(self, username, password, publicKey):
        message = {
            "command": "register",
            "payload": {"username": username, "password": password}
        }
        self.send_encrypted_message(json.dumps(message), publicKey)
        return self.recvMsg()

    def login(self, username, password):
        message = {
            "username": username, "password": password
        }
        self.send_aes(json.dumps(message), "login")
        
    def new_game(self, score, level):
        message = {
            "score": f"{score}", "level": f"{level}"
        }
        self.send_aes(json.dumps(message), "new_game")
        

    def start_game(self, username, publicKey):
        message = {
            "command": "start_game",
            "payload": {"username": username}
        }
        self.send_encrypted_message(message, publicKey)
        return self.recvMsg()

    def player_move(self, username, direction, publicKey):
        message = {
            "command": "player_move",
            "payload": {"username": username, "direction": direction}
        }
        self.send_encrypted_message(message, publicKey)
        return self.recvMsg()
    
def create_tcp_client(server_info: ServerInfo):
    clientTCP = TCP_Client(server_info.get_IP(), int(server_info.get_Port()))
    return clientTCP
    
def receive_udp_multicast() -> ServerInfo:
    multicast_group = '224.1.1.1'
    server_port = 5007

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', server_port))

    group = socket.inet_aton(multicast_group)
    mreq = struct.pack('4sL', group, socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    try:
        for i in range(5):
            data, address = sock.recvfrom(1024)
            try:
                server_info = ServerInfo.model_validate_json(data.decode())
                print(f"Received valid server info from {server_info.TCPConn.full_address()} - {server_info.Name}")
                # print(f"Public Key: {server_info.PublicKey}")
                # print("SERVER", server_info)
                break
            except ValidationError as ve:
                print(f"Validation error: {ve}")
            except json.JSONDecodeError as je:
                print(f"JSON decode error: {je}")
            except Exception as e:
                print(f"Unexpected error: {e}")
    finally:
        sock.close()
        print("PUBLIC KEY", server_info.PublicKey)
        return server_info
        
    
def main():
    server_info = receive_udp_multicast()
    try:
        clientTCP = create_tcp_client(server_info)
        print("Connected to TCP server")
    except socket.error as e:
        print(f"Could not create client: {e}")

    # # print(f"AES key: {aes_key}")
    # # challange = clientTCP.generate_challenge()
    print(clientTCP.challange(server_info.PublicKey))
    # # encrypted_message = clientTCP.recvMsg(1024)
    # print(str(encrypted_message))
    # decrypted_response = clientTCP.decrypt_aes(aes_key, str(encrypted_message))
    # print(decrypted_response)
    # print("DECRYPTED STRING", str(decrypted_response.decode('utf-8')))
    # response_data = json.loads(decrypted_response)
    # print(response_data)


    #  to dziala
    # key = get_random_bytes(32)
    # challange = get_random_bytes(8)
    # id = uuid.uuid4()

    # message = {
    #         'command': 'siema',
    #         'aes_key': base64.b64encode(key).decode('utf-8'),
    #     }
    # clientTCP.send_encrypted_message(message, server_info.PublicKey)
    # data = json.dumps(message)

    # tu jest AES
    
    # key = get_random_bytes(32)
    clientTCP.login("user1", "password1")
    # data = {"username": "user1", "password": "password1"}
    # clientTCP.send_aes(json.dumps(data), "login")
    # print("RECEIVED MESASGE DECRYPTED:", clientTCP.recv_aes(aes_key))
    login_response = json.loads(clientTCP.recv_aes())
    print("LOGIN RESPONSE", login_response)
    print("WUTAJ W GRZE GRACZU")
    # score, level = start_game()
    # data = {"score": f"{score}", "level": f"{level}"}
    # clientTCP.send_aes(json.dumps(data), "new_game")
    clientTCP.new_game(2,1)
    print(clientTCP.recv_aes())
    
    # cipher = AES.new(aes_key, AES.MODE_CTR)
    # ct_bytes = cipher.encrypt(data.encode('utf-8'))
    # nonce = base64.b64encode(cipher.nonce).decode('utf-8')
    # ct = base64.b64encode(ct_bytes).decode('utf-8')
    # result = json.dumps({'command': "siema", 'nonce': nonce, 'cipher_text': ct})

    # print("Key:", base64.b64encode(aes_key).decode('utf-8'))
    # encoded_message = base64.b64encode(result.encode('utf-8'))
    # clientTCP.sendMsg(encoded_message)
    # base64Message = clientTCP.recvMsg(1024)
    
    # try:
    #     decoded_message = base64.b64decode(base64Message)
    #     b64 = json.loads(decoded_message)
    #     nonce = base64.b64decode(b64['nonce'])
    #     ct = base64.b64decode(b64['cipher_text'])
    #     # print("New nonce", str(nonce.decode("utf-8")))
    #     # print("New ct", str(ct.decode("utf-8")))
    #     cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    #     pt = cipher.decrypt(ct)
    #     print("The message was:", pt.decode('utf-8'))
    # except (ValueError, KeyError) as e:
    #     print("Incorrect decryption", e)
    # print(clientTCP.register('player1', 'password123', server_info.PublicKey))
    # message = "Hello, server !"
    # sendMsg = clientTCP.sendMsg(message)
    # if sendMsg is not None:
    #     print(f"Send to server server: {message}")
    # else:
    #     print("No response send to server.")
    #     clientTCP.close()
    #     return
    
    # recvMsg = clientTCP.recvMsg()
    # if recvMsg is not None:
    #     print(f"Received from server: {recvMsg}")
    # else:
    #     print("No response received from server.")
    #     clientTCP.close()
    #     return
# if __name__ == "__main__":
#     main()
#     print("Closing Client")