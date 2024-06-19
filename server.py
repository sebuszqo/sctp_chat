import socket
import struct
import threading
import time

def send_server_info(sock, multicast_group, server_port, sctp_port):
    while True:
        server_info = f"Server available at {sock.getsockname()[0]} on SCTP port {sctp_port}"
        sock.sendto(server_info.encode(), (multicast_group, server_port))
        print("Server info sent!")
        time.sleep(5)


def setup_sctp_server(sctp_port):
    # Tworzenie gniazda SCTP
    sctp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
    sctp_sock.bind(('', sctp_port))
    sctp_sock.listen(5)
    print(f"SCTP server listening on port {sctp_port}")

    # Obsługa przychodzących połączeń
    while True:
        connection, addr = sctp_sock.accept()
        print(f"Connected to {addr}")
        # Tutaj można uruchomić wątek do obsługi tego konkretnego klienta


def main():
    multicast_group = '224.1.1.1'
    multicast_port = 5007
    sctp_port = 5001

    # Ustawienia gniazda multicast
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('b', 2))

    # Wątek multicast
    multicast_thread = threading.Thread(target=send_server_info, args=(sock, multicast_group, multicast_port, sctp_port))
    multicast_thread.start()

    # Uruchomienie serwera SCTP
    setup_sctp_server(sctp_port)

if __name__ == "__main__":
    main()
