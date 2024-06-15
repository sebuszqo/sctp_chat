package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
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

type DefaultRequest struct {
	Command    string `json:"command"`
	Nonce      string `json:"nonce"`
	CipherText string `json:"cipher_text"`
}

type ExchangeRequest struct {
	Command string `json:"command"`
	AESKey  string `json:"aes_key"`
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
	Exchange
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
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
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

func startTCPServer(IPv4Address string, port int, privatePEM *rsa.PrivateKey) (ServerConnection, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return ServerConnection{}, err
	}

	addr := syscall.SockaddrInet4{Port: port, Addr: [4]byte(net.ParseIP(IPv4Address).To4())}

	err = syscall.Bind(fd, &addr)
	if err != nil {
		syscall.Close(fd)
		return ServerConnection{}, err
	}

	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		fmt.Printf("Error setting SO_REUSEADDR: %v\n", err)
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
			go handleConnection(connFd, privatePEM)
		}
	}()

	serverConnConfig := ServerConnection{
		IP:   IPv4Address,
		Port: fmt.Sprint(port),
	}

	return serverConnConfig, nil
}

func handleConnection(connFd int, privPEM *rsa.PrivateKey) {
	defer syscall.Close(connFd)
	buffer := make([]byte, 1024)
	var decodedAES []byte
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

		fmt.Println("OTRZUMAELM?", string(buffer[:n]))
		// return
		log.Printf("Received encrypted message: %s", string(buffer[:n]))

		// ciphertext := buffer
		// fmt.Println("CIPER", ciphertext)
		// b64data := ciphertext[strings.IndexByte(string(ciphertext), ',')+1:]
		// fmt.Println("B64", b64data)
		// cipherTexttoDe, err := base64.StdEncoding.DecodeString(string(b64data))
		// fmt.Println(cipherTexttoDe)
		// if err != nil {
		// log.Fatalln("ERROR TU", err)
		// }
		//  dodalem tutaj to
		ciphertext, err := base64.StdEncoding.DecodeString(string(buffer[:n]))
		if err != nil {
			log.Println("BŁ/*  */")
		}

		fmt.Println("after BAse64", string(ciphertext))

		var msg Message
		err = json.Unmarshal([]byte(ciphertext), &msg)
		if err != nil {
			log.Printf("Error unmarshaling message: %v", err)
			continue
		}

		switch msg.Command {
		case "exchange":
			var payload ExchangeRequest
			json.Unmarshal(ciphertext, &payload)
			aesKEy, err := base64.StdEncoding.DecodeString(payload.AESKey)
			if err != nil {
				log.Fatalln("ERRRRRROR", err)
			}
			decryptedJSONPayload, err := DecryptWithPrivateKey(aesKEy, privPEM)
			if err != nil {
				log.Printf("Error decrypting message: %v", err)
				continue
			}
			fmt.Println("DECRYPTED?", string(decryptedJSONPayload))
			decodedAES = decryptedJSONPayload

			// fmt.Println("AES b64", payload.AESKey)
			// decodedAES, err = base64.StdEncoding.DecodeString(payload.AESKey)
			// if err != nil {
			// 	fmt.Println("ERROR AES !", err)
			// }
			// encryptedData, _ := EncryptAES([]byte(decodedAES), []byte("SUCCESS"))
			// syscall.Write(connFd, []byte(base64Encode(encryptedData)))
			// jsonData, err := json.Marshal(response)
			// if err != nil {
			// 	fmt.Println("Error marshaling map:", err)
			// 	return
			// }
			// encryptedResponse, err := encryptAES(decodedAES, jsonData)
			// if err != nil {
			// 	fmt.Println("ERROR DURING AES ENCRYPTION", encryptedResponse)
			// }
			// syscall.Write(connFd, []byte(encryptedResponse))
			// fmt.Println("SENDED: ", encryptedResponse)
			// fmt.Println("SENDED byte: ", []byte(encryptedResponse))

			// fmt.Println("AES b64", ba(payload.AESKey))
			// fmt.Println("CHALLANGE b64", payload.Challenge)
			// challenge, err := base64.StdEncoding.DecodeString(msg["challenge"])
			// if err != nil {
			// 	fmt.Println("Failed to decode challenge:", err)
			// 	conn.Write([]byte("Failed to decode challenge"))
			// 	return
			// }
			// fmt.Printf("Challenge: %x\n", challenge)
		case "register":
			var payload RegisterRequest
			jsonPayload, _ := json.Marshal(msg.Payload)
			json.Unmarshal(jsonPayload, &payload)
			log.Printf("DECRYPTED PAYLOAD: %+v", payload)
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
			log.Printf("ENCRYPTED PAYLOAD: %s", jsonPayload)
			json.Unmarshal(jsonPayload, &payload)
			log.Printf("DECRYPTED PAYLOAD: %+v", payload)
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
			log.Printf("ENCRYPTED PAYLOAD: %s", jsonPayload)
			json.Unmarshal(jsonPayload, &payload)
			log.Printf("DECRYPTED PAYLOAD: %+v", payload)
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
			log.Printf("ENCRYPTED PAYLOAD: %s", jsonPayload)
			json.Unmarshal(jsonPayload, &payload)
			log.Printf("DECRYPTED PAYLOAD: %+v", payload)
		case "siema":
			var payload DefaultRequest
			json.Unmarshal(ciphertext, &payload)
			fmt.Println("DECRYPTING DATA", payload.Nonce, payload.CipherText, payload.Command)
			aesKey, err := base64.StdEncoding.DecodeString(string(decodedAES))
			decrypted, err := DecryptAES(aesKey, payload.Nonce, payload.CipherText)
			if err != nil {
				log.Fatalln("Error during AES decryption:", err)
			}
			fmt.Println("Decrypted data:", string(decrypted))
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

// func GenerateKeyPair() (*KeyPair, error) {
// 	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
// 	if err != nil {
// 		return nil, err
// 	}

// 	publicKey := &privateKey.PublicKey

// 	// Marshalowanie klucza prywatnego do PEM
// 	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
// 	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
// 		Type:  "RSA PRIVATE KEY",
// 		Bytes: privateKeyBytes,
// 	})

// 	// Marshalowanie klucza publicznego do PEM
// 	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
// 		Type:  "RSA PUBLIC KEY",
// 		Bytes: publicKeyBytes,
// 	})

// 	return &KeyPair{
// 		PublicKey:  string(publicKeyPEM),
// 		PrivateKey: string(privateKeyPEM),
// 	}, nil
// }

func GenerateKeyPair(bits int) (KeyPair, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return KeyPair{}, err
	}

	return KeyPair{PrivateKey: privkey, PublicKey: &privkey.PublicKey}, nil
}

func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatal(err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		log.Fatal(err)
	}
	return ciphertext
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func base64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func base64Decode(src []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(src))
}

func DecryptAES(key []byte, nonceB64 string, ciphertextB64 string) ([]byte, error) {
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Ensure nonce length is appropriate
	if len(nonce) != 8 {
		return nil, fmt.Errorf("nonce length must be 8 bytes, got %d bytes", len(nonce))
	}

	// Create a 16-byte IV for AES-CTR
	iv := make([]byte, aes.BlockSize)
	copy(iv, nonce)

	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// EncryptAES encrypts data using AES in CTR mode.
func EncryptAES(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, nonce)
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)

	result := map[string]string{
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

func main() {
	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		log.Fatalln(err)
	}
	publicKey := PublicKeyToBytes(keyPair.PublicKey)
	privateKey := PrivateKeyToBytes(keyPair.PrivateKey)
	fmt.Println("PRIVATE", string(privateKey))
	fmt.Println("PRIVATE", *keyPair.PrivateKey)
	fmt.Println("PUBLIC", string(publicKey))

	IPv4Address, err := getLocalIP()
	if err != nil {
		log.Fatalln(err.Error())
	}

	serverConnConfig, err := startTCPServer(IPv4Address, 3001, keyPair.PrivateKey)
	if err != nil {
		log.Fatalln(err.Error())
	}

	fmt.Println(keyPair.PrivateKey)
	gameType := snake
	server := serverInfo{
		Name:      "Serwer to play games",
		GameType:  gameType,
		TCPConn:   serverConnConfig,
		PublicKey: string(publicKey),
		Command:   Start,
	}
	serverInfo, conn, err := configureUDP(server)
	if err != nil {
		log.Fatal(err.Error())
	}

	const maxAttempts = 5
	attemptCount := 0
	sendMulticastFor := 200 * time.Second

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
