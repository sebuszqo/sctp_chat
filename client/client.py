import socket
import json
import struct
from pydantic import BaseModel, ValidationError, field_validator
from enum import Enum

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
        try:
            self.client_socket.connect((self.server_ip, self.server_port))
        except socket.error as e:
            print(f"Failed to connect to {self.server_ip}:{self.server_port}. Error: {e}")
            raise
        
    def sendMsg(self, message: str):
        try:
            if not isinstance(message, bytes):
                message = str(message).encode()
            elif not isinstance(message, str):
                raise ValueError("Message must be either str or bytes")
            self.client_socket.send(message)
            return not None
        except socket.error as e:
            print(f"Failed to send message. Error: {e}")
            return None
        except ValueError:
            print(f"Failed to send message. Error: {e}")

    def recvMsg(self, buffer_size=1024):
        try:
            message = self.client_socket.recv(buffer_size)
            return message.decode('utf-8')
        except socket.error as e:
            print(f"Failed to receive message. Error: {e}")
            return None

    def close(self):
        if self.client_socket:
            self.client_socket.close()
        
def main():
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
                print(f"Public Key: {server_info.Command}")
                break
            except ValidationError as ve:
                print(f"Validation error: {ve}")
            except json.JSONDecodeError as je:
                print(f"JSON decode error: {je}")
            except Exception as e:
                print(f"Unexpected error: {e}")
    finally:
        sock.close()

    try:
        clientTCP = TCP_Client(server_info.get_IP(), int(server_info.get_Port()))
        print("Connected to TCP server")
    except socket.error as e:
        print(f"Could not create client: {e}")
        
    message = "Hello, server !"
    sendMsg = clientTCP.sendMsg(message)
    if sendMsg is not None:
        print(f"Send to server server: {message}")
    else:
        print("No response send to server.")
        clientTCP.close()
        return
    
    recvMsg = clientTCP.recvMsg()
    if recvMsg is not None:
        print(f"Received from server: {recvMsg}")
    else:
        print("No response received from server.")
        clientTCP.close()
        return
if __name__ == "__main__":
    main()
    print("Closing Client")