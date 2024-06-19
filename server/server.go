package server

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

const MulticastGroup = "224.1.1.1:5007"

type ServerInfo struct {
	Name      string
	GameType  GameType
	TCPConn   ServerConnection
	PublicKey string
	Command   Command
}

var (
	users      map[string]User
	userGames  map[string][]Game
	highScores []HighScore
)

func init() {
	users = map[string]User{
		"user1": {ID: "1", Username: "user1", Password: "password1"},
		"user2": {ID: "2", Username: "user2", Password: "password2"},
		"user3": {ID: "3", Username: "user3", Password: "password3"},
	}
	userGames = make(map[string][]Game)
	UpdateHighScores("user1", 6)
	UpdateHighScores("user2", 4)
	UpdateHighScores("user3", 2)
	AddGame("user1", 5, 2)
	AddGame("user1", 7, 3)
	AddGame("user1", 1, 1)
	AddGame("user2", 5, 2)
}

func GetLocalIP() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue
			}

			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("no active network interface found")
}

func TryToStartTCPServer(IPv4Address string, minPort, maxPort int, privateKey *rsa.PrivateKey) (ServerConnection, error) {
	for port := minPort; port <= maxPort; port++ {
		serverConnConfig, err := StartTCPServer(IPv4Address, port, privateKey)
		if err == nil {
			return serverConnConfig, nil
		}
		if err != syscall.EADDRINUSE {
			log.Printf("Failed to start server on port %d: %v \n", port, err)
		}
	}
	return ServerConnection{}, fmt.Errorf("no available ports in range %d-%d", minPort, maxPort)
}

func StartTCPServer(IPv4Address string, port int, privateKey *rsa.PrivateKey) (ServerConnection, error) {
	log.Println("Starting TCP server")
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return ServerConnection{}, err
	}

	addr := syscall.SockaddrInet4{Port: port, Addr: [4]byte(net.ParseIP(IPv4Address).To4())}

	log.Println("Binding socket to address struct")
	err = syscall.Bind(fd, &addr)
	if err != nil {
		err := syscall.Close(fd)
		if err != nil {
			return ServerConnection{}, err
		}
		return ServerConnection{}, err
	}

	log.Println("Setting sock options to enable SO_REUSEADDR.")
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		fmt.Printf("Error setting SO_REUSEADDR: %v\n", err)
		return ServerConnection{}, err
	}

	log.Println("Starting Listening to new connections")
	err = syscall.Listen(fd, syscall.SOMAXCONN)
	if err != nil {
		err := syscall.Close(fd)
		if err != nil {
			return ServerConnection{}, err
		}
		return ServerConnection{}, err
	}

	go func() {
		defer syscall.Close(fd)
		for {
			log.Println("Accepting new connection.")
			connFd, _, err := syscall.Accept(fd)
			if err != nil {
				log.Println("Failed to accept connection:", err)
				continue
			}
			go HandleConnection(connFd, privateKey)
		}
	}()

	serverConnConfig := ServerConnection{
		IP:   IPv4Address,
		Port: fmt.Sprint(port),
	}

	return serverConnConfig, nil
}

func HandleConnection(connFd int, privPEM *rsa.PrivateKey) {
	defer syscall.Close(connFd)
	buffer := make([]byte, 1024)
	logged := false
	var userName string
	var decodedAES []byte
	for {
		log.Println("Starting handling connections")
		n, err := syscall.Read(connFd, buffer)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			log.Printf("Error reading from connection: %v \n", err)
			return
		}
		if n == 0 {
			log.Printf("Client closed the connection \n")
			return
		}

		log.Printf("Received encrypted message: %s\n", string(buffer[:n]))

		ciphertext, err := base64.StdEncoding.DecodeString(string(buffer[:n]))
		if err != nil {
			log.Println("BŁ/*  */")
		}

		log.Println("After Base64 decode", string(ciphertext))

		var msg Message
		err = json.Unmarshal([]byte(ciphertext), &msg)
		if err != nil {
			log.Printf("Error unmarshaling message: %v \n", err)
			continue
		}

		log.Println("Received command", msg.Command)
		switch msg.Command {
		case "exchange":
			log.Println("Handling Exchange crypto keys Request.")
			var payload ExchangeRequest
			json.Unmarshal(ciphertext, &payload)
			aesKEy, err := base64.StdEncoding.DecodeString(payload.AESKey)
			if err != nil {
				log.Fatalln("Error during decoding string from base64", err)
			}
			decryptedJSONPayload, err := DecryptWithPrivateKey(aesKEy, privPEM)
			if err != nil {
				log.Printf("Error decrypting message: %v \n", err)
				continue
			}
			decodedAES = decryptedJSONPayload
		case "register":
			log.Println("Handling Register Request.")
			HandleRegister(connFd, msg)
		case "login":
			log.Println("Handling Login Request.")
			HandleLogin(connFd, decodedAES, ciphertext, &logged, &userName)
		case "new_game":
			log.Println("Handling New Game Request for user: ", userName)
			HandleNewGame(connFd, msg, ciphertext, privPEM, decodedAES, userName)
		case "view_high_scores":
			log.Println("Handling High Score Request for user: ", userName)
			HandleViewHighScores(connFd, decodedAES)
		case "view_last_games":
			log.Println("Handling View Last Games Request for user: ", userName)
			HandleViewLastGames(connFd, decodedAES, userName)
		case "player_move":
			HandlePlayerMove(msg)
		}
	}
}

func ConfigureUDP(serverInfo ServerInfo) ([]byte, int, error) {
	byteServerInfo, err := json.Marshal(serverInfo)
	if err != nil {
		log.Fatalf(err.Error())
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, -1, err
	}

	return byteServerInfo, fd, nil
}

func SendMulticast(multicastGroup string, serverInfo []byte, fd int, poll time.Duration, done <-chan bool, errorChan chan<- error, wg *sync.WaitGroup) {
	tick := time.NewTicker(poll)
	defer tick.Stop()
	defer wg.Done()

	for {
		select {
		case <-done:
			fmt.Println("Stopping UDP multicast")
			return
		case <-tick.C:
			addrParts := strings.Split(multicastGroup, ":")
			ip := net.ParseIP(addrParts[0]).To4()
			port := addrParts[1]
			portNum := 0
			fmt.Sscanf(port, "%d", &portNum)

			sockAddr := &syscall.SockaddrInet4{
				Port: portNum,
				Addr: [4]byte(ip),
			}

			err := syscall.Sendto(fd, serverInfo, 0, sockAddr)
			if err != nil {
				fmt.Println("Error sending message:", err)
				errorChan <- &MulticastError{Msg: err.Error()}
				return
			}
		}
	}
}
