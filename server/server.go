package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type StartGameRequest struct {
	Username string `json:"username"`
}

type StartGameResponse struct {
	Success   bool             `json:"success"`
	Message   string           `json:"message"`
	Obstacles []map[string]int `json:"obstacles"`
}

type GameUpdate struct {
	Obstacles []map[string]int `json:"obstacles"`
	Players   []PlayerState    `json:"players"`
}

type PlayerState struct {
	Username string `json:"username"`
	X        int    `json:"x"`
	Y        int    `json:"y"`
	Length   int    `json:"length"`
}

type PlayerMove struct {
	Username  string `json:"username"`
	Direction string `json:"direction"`
}

type Message struct {
	Command string      `json:"command"`
	Payload interface{} `json:"payload"`
}

const multicastGroup = "224.1.1.1:5007"

type multicastError struct {
	msg string
}

func (e *multicastError) Error() string {
	return e.msg
}

type Command int

const (
	Start Command = iota
	Stop
	Restart
	Status
	Login
)

func (c Command) String() string {
	return [...]string{"Start", "Stop", "Restart", "Status"}[c]
}

func (c Command) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

type gameType string

const (
	snake     gameType = "snake"
	ticTacToe gameType = "ticTacToe"
)

type ServerConnection struct {
	IP   string
	Port string
}

type KeyPair struct {
	PublicKey  string
	privateKey string
}

type serverInfo struct {
	Name      string
	GameType  gameType
	TCPConn   ServerConnection
	PublicKey string
	Command   Command
}

func getLocalIP() (string, error) {
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

func startTCPServer(IPv4Address string) (ServerConnection, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return ServerConnection{}, err
	}

	addr := syscall.SockaddrInet4{Port: 3001, Addr: [4]byte(net.ParseIP(IPv4Address).To4())}

	err = syscall.Bind(fd, &addr)
	if err != nil {
		syscall.Close(fd)
		return ServerConnection{}, err
	}

	err = syscall.Listen(fd, syscall.SOMAXCONN)
	if err != nil {
		syscall.Close(fd)
		return ServerConnection{}, err
	}

	go func() {
		defer syscall.Close(fd)
		for {
			connFd, _, err := syscall.Accept(fd)
			if err != nil {
				log.Println("Failed to accept connection:", err)
				continue
			}
			go handleConnection(connFd)
		}
	}()

	serverConnConfig := ServerConnection{
		IP:   IPv4Address,
		Port: "3001",
	}

	return serverConnConfig, nil
}

func handleConnection(connFd int) {
	defer syscall.Close(connFd)
	buffer := make([]byte, 1024)
	for {
		n, err := syscall.Read(connFd, buffer)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			log.Printf("Error reading from connection: %v", err)
			return
		}
		if n == 0 {
			return
		}

		var msg Message
		fmt.Println("BUFFER 1", string(buffer[:n]))
		fmt.Println("BUFFER 2", string(buffer))
		err = json.Unmarshal(buffer[:n], &msg)
		if err != nil {
			log.Printf("Error unmarshaling message: %v", err)
			continue
		}
		switch msg.Command {
		case "register":
			var payload RegisterRequest
			jsonPayload, _ := json.Marshal(msg.Payload)
			json.Unmarshal(jsonPayload, &payload)
			response := RegisterResponse{
				Success: true,
				Message: "Registration successful",
			}
			jsonResponse, _ := json.Marshal(Message{
				Command: "register_response",
				Payload: response,
			})
			syscall.Write(connFd, jsonResponse)

		case "login":
			var payload LoginRequest
			jsonPayload, _ := json.Marshal(msg.Payload)
			json.Unmarshal(jsonPayload, &payload)
			response := LoginResponse{
				Success: true,
				Message: "Login successful",
			}
			jsonResponse, _ := json.Marshal(Message{
				Command: "login_response",
				Payload: response,
			})
			syscall.Write(connFd, jsonResponse)

		case "start_game":
			var payload StartGameRequest
			jsonPayload, _ := json.Marshal(msg.Payload)
			json.Unmarshal(jsonPayload, &payload)
			response := StartGameResponse{
				Success: true,
				Message: "Game started",
				Obstacles: []map[string]int{
					{"x": 5, "y": 5},
					{"x": 10, "y": 10},
				},
			}
			jsonResponse, _ := json.Marshal(Message{
				Command: "start_game_response",
				Payload: response,
			})
			syscall.Write(connFd, jsonResponse)

		case "player_move":
			var payload PlayerMove
			jsonPayload, _ := json.Marshal(msg.Payload)
			json.Unmarshal(jsonPayload, &payload)
			log.Printf("Player %s moved %s", payload.Username, payload.Direction)
			// Update game state accordingly

		default:
			log.Printf("Unknown command: %s", msg.Command)
		}

	}
}

func configureUDP(serverInfo serverInfo) ([]byte, int, error) {
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

func sendMulticast(multicastGroup string, serverInfo []byte, fd int, poll time.Duration, done <-chan bool, errorChan chan<- error, wg *sync.WaitGroup) {
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
				errorChan <- &multicastError{msg: err.Error()}
				return
			}
		}
	}
}

func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	publicKey := &privateKey.PublicKey

	// Marshalowanie klucza prywatnego do PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Marshalowanie klucza publicznego do PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return &KeyPair{
		PublicKey:  string(publicKeyPEM),
		privateKey: string(privateKeyPEM),
	}, nil
}

func EncryptWithPublicKey(msg string, pubPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, fmt.Errorf("public key error")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(msg), nil)
}

func DecryptWithPrivateKey(ciphertext []byte, privPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return "", fmt.Errorf("private key error")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func main() {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		log.Fatalln(err)
	}

	IPv4Address, err := getLocalIP()
	if err != nil {
		log.Fatalln(err.Error())
	}

	serverConnConfig, err := startTCPServer(IPv4Address)
	if err != nil {
		log.Fatalln(err.Error())
	}
	gameType := snake
	server := serverInfo{
		Name:      "Serwer to play games",
		GameType:  gameType,
		TCPConn:   serverConnConfig,
		PublicKey: keyPair.PublicKey,
		Command:   Start,
	}
	serverInfo, conn, err := configureUDP(server)
	if err != nil {
		log.Fatal(err.Error())
	}

	const maxAttempts = 5
	attemptCount := 0
	sendMulticastFor := 10 * time.Second

	var multicastWaitGroup sync.WaitGroup

	for attemptCount < maxAttempts {
		multicastDoneChan := make(chan bool, 1)
		multicastErrorChan := make(chan error, 1)

		multicastWaitGroup.Add(1)
		go sendMulticast(multicastGroup, serverInfo, conn, 1*time.Second, multicastDoneChan, multicastErrorChan, &multicastWaitGroup)

		select {
		case err := <-multicastErrorChan:
			fmt.Printf("Received multicast error: %s\n", err)
			attemptCount++
			fmt.Printf("Retrying... Attempt %d of %d\n", attemptCount, maxAttempts)
			multicastWaitGroup.Wait()
			continue
		case <-time.After(sendMulticastFor):
			close(multicastDoneChan)
			multicastWaitGroup.Wait()
			fmt.Println("Multicast period completed without errors")
			return
		}
	}

	fmt.Println("More than 5 attempts to restart multicast, closing app...")
}
