import socket
import struct

# Ustawienia multicast
multicast_group = '224.1.1.1'
server_port = 5007

# Utworzenie gniazda UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('', server_port))

# Ustawienie gniazda do dołączenia do grupy multicast
group = socket.inet_aton(multicast_group)
mreq = struct.pack('4sL', group, socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

# Nasłuchiwanie na wiadomości
try:
    while True:
        print("Waiting to receive message...")
        data, address = sock.recvfrom(1024)
        print(f"Received {len(data)} bytes from {address}: {data.decode()}")
        
        # Tutaj można dodać logikę do połączenia z serwerem
finally:
    sock.close()
