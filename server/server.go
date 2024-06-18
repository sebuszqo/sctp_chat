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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ViewHighScoresResponse struct {
	HighScores []HighScore `json:"high_scores"`
	Success    bool        `json:"success"`
}

type ViewLastGamesResponse struct {
	LastGames []Game `json:"last_games"`
	Success   bool   `json:"success"`
}

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
	Success bool `json:"success"`
}

type NewGameResponse struct {
	Success bool `json:"success"`
}

type StartGameRequest struct {
	Username string `json:"username"`
}

type NewGameRequest struct {
	Score string `json:"score"`
	Level string `json:"level"`
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

type User struct {
	ID       string
	Username string `json:"username"`
	Password string `json:"password"`
}

type Game struct {
	Score int `json:"score"`
	Level int `json:"level"`
}

type HighScore struct {
	Username string `json:"username"`
	Score    int    `json:"score"`
}

var (
	users           map[string]User
	userGames       map[string][]Game
	highScores      []HighScore
	highScoresMutex sync.Mutex
	userGamesMutex  sync.Mutex
)

// init sever with some testing data - will be migrated to be a postgres database
func init() {
	users = map[string]User{
		"user1": {ID: "1", Username: "user1", Password: "password1"},
		"user2": {ID: "2", Username: "user2", Password: "password2"},
		"user3": {ID: "3", Username: "user3", Password: "password3"},
	}
	userGames = make(map[string][]Game)
	updateHighScores("user1", 6)
	updateHighScores("user2", 4)
	updateHighScores("user3", 2)
	addGame("user1", 5, 2)
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

func tryToStartTCPServer(IPv4Address string, minPort, maxPort int, privateKey *rsa.PrivateKey) (ServerConnection, error) {
	for port := minPort; port <= maxPort; port++ {
		serverConnConfig, err := startTCPServer(IPv4Address, port, privateKey)
		if err == nil {
			return serverConnConfig, nil
		}
		if err != syscall.EADDRINUSE {
			log.Printf("Failed to start server on port %d: %v", port, err)
		}
	}
	return ServerConnection{}, fmt.Errorf("no available ports in range %d-%d", minPort, maxPort)
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
	logged := false
	var userName string
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
			log.Printf("Client closed the connection")
			return
		}

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

		fmt.Println("MESSAGE COMMAND", msg.Command)
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
			var payload DefaultRequest
			json.Unmarshal(ciphertext, &payload)
			fmt.Println("DECRYPTING DATA", payload.Nonce, payload.CipherText, payload.Command)
			aesKey, err := base64.StdEncoding.DecodeString(string(decodedAES))
			decrypted, err := DecryptAES(aesKey, payload.Nonce, payload.CipherText)
			if err != nil {
				log.Fatalln("Error during AES decryption:", err)
			}
			var incomingUser User
			json.Unmarshal(decrypted, &incomingUser)
			fmt.Println("Decrypted data:", string(decrypted))
			for login, user := range users {
				if login == incomingUser.Username && user.Password == incomingUser.Password {
					logged = true
					fmt.Printf("USER: %s logged \n", login)
					userName = incomingUser.Username
				}
			}
			data, err := json.Marshal(LoginResponse{
				Success: logged,
			})

			if err != nil {
				log.Fatalln("ERROR DURING MARSHALING", err)
			}
			encyrption, err := EncryptAES(aesKey, data)
			if err != nil {
				log.Fatalln("ERRRR", err)
			}
			encrytedData := base64.StdEncoding.EncodeToString(encyrption)
			syscall.Write(connFd, []byte(encrytedData))
		case "new_game":
			var payload DefaultRequest
			json.Unmarshal(ciphertext, &payload)
			fmt.Println("DECRYPTING DATA", payload.Nonce, payload.CipherText, payload.Command)
			aesKey, err := base64.StdEncoding.DecodeString(string(decodedAES))
			decrypted, err := DecryptAES(aesKey, payload.Nonce, payload.CipherText)
			if err != nil {
				log.Fatalln("Error during AES decryption:", err)
			}
			var newGame NewGameRequest
			json.Unmarshal(decrypted, &newGame)
			fmt.Println("Decrypted data:", string(decrypted))
			score, err := strconv.Atoi(newGame.Score)
			if err != nil {
				log.Fatalln("ERROR during converting string to int")
			}
			level, err := strconv.Atoi(newGame.Level)
			if err != nil {
				log.Fatalln("ERROR during converting string to int")
			}
			updateHighScores(userName, score)
			addGame(userName, score, level)

			data, err := json.Marshal(NewGameResponse{
				Success: true,
			})

			if err != nil {
				log.Fatalln("ERROR DURING MARSHALING", err)
			}
			encyrption, err := EncryptAES(aesKey, data)
			if err != nil {
				log.Fatalln("ERRRR", err)
			}
			encrytedData := base64.StdEncoding.EncodeToString(encyrption)
			syscall.Write(connFd, []byte(encrytedData))
		case "view_high_scores":
			// var payload DefaultRequest
			// json.Unmarshal(ciphertext, &payload)
			// fmt.Println("DECRYPTING DATA", payload.Nonce, payload.CipherText, payload.Command)
			aesKey, err := base64.StdEncoding.DecodeString(string(decodedAES))
			// if err != nil {
			// 	log.Fatalln("Error decoding AES key:", err)
			// }
			// decrypted, err := DecryptAES(aesKey, payload.Nonce, payload.CipherText)
			// if err != nil {
			// 	log.Fatalln("Error during AES decryption:", err)
			// }
			// var incomingRequest DefaultRequest
			// json.Unmarshal(decrypted, &incomingRequest)
			// fmt.Println("Decrypted data:", string(decrypted))

			highScoresMutex.Lock()
			highScoresResponse := highScores
			highScoresMutex.Unlock()
			fmt.Println("CURRENT HIGH SCORE: ", highScoresResponse)

			data, err := json.Marshal(ViewHighScoresResponse{
				HighScores: highScoresResponse,
				Success:    true,
			})
			if err != nil {
				log.Fatalln("ERROR DURING MARSHALING", err)
			}
			encryption, err := EncryptAES(aesKey, data)
			if err != nil {
				log.Fatalln("ERRRR", err)
			}
			encryptedData := base64.StdEncoding.EncodeToString(encryption)
			syscall.Write(connFd, []byte(encryptedData))
		case "view_last_games":
			aesKey, err := base64.StdEncoding.DecodeString(string(decodedAES))
			lastGames := viewLastGames(userName)

			data, err := json.Marshal(ViewLastGamesResponse{
				LastGames: lastGames,
				Success:   true,
			})
			fmt.Println("RETURNING LAST GAMES: ", lastGames)
			if err != nil {
				log.Fatalln("ERROR DURING MARSHALING", err)
			}
			encryption, err := EncryptAES(aesKey, data)
			if err != nil {
				log.Fatalln("Error during AES encryption:", err)
			}
			encryptedData := base64.StdEncoding.EncodeToString(encryption)
			syscall.Write(connFd, []byte(encryptedData))
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
			var user User
			json.Unmarshal(decrypted, &user)
			fmt.Println("Decrypted data:", string(decrypted))
			siema := "siama witaj moj drugi czlowieku"
			encyrption, err := EncryptAES(aesKey, []byte(siema))
			if err != nil {
				log.Fatalln("ERRRR", err)
			}
			encrytedData := base64.StdEncoding.EncodeToString(encyrption)
			syscall.Write(connFd, []byte(encrytedData))
		}
	}
}

func updateHighScores(username string, score int) {
	highScoresMutex.Lock()
	defer highScoresMutex.Unlock()

	for i, hs := range highScores {
		if hs.Username == username {
			if score > hs.Score {
				highScores[i].Score = score
			}
			sort.Slice(highScores, func(i, j int) bool {
				return highScores[i].Score > highScores[j].Score
			})
			return
		}
	}
	highScores = append(highScores, HighScore{Username: username, Score: score})
	sort.Slice(highScores, func(i, j int) bool {
		return highScores[i].Score > highScores[j].Score
	})
	if len(highScores) > 10 {
		highScores = highScores[:10]
	}
}

func viewLastGames(username string) []Game {
	userGamesMutex.Lock()
	defer userGamesMutex.Unlock()
	return userGames[username]
}

func addGame(username string, score int, level int) {
	userGamesMutex.Lock()
	defer userGamesMutex.Unlock()

	game := Game{
		Score: score,
		Level: level,
	}
	userGames[username] = append(userGames[username], game)
	if len(userGames[username]) > 10 {
		userGames[username] = userGames[username][:10]
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

	nonce := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	fullNonce := make([]byte, aes.BlockSize)
	copy(fullNonce, nonce)

	stream := cipher.NewCTR(block, fullNonce)
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)

	result := map[string]string{
		"nonce":       base64.StdEncoding.EncodeToString(nonce),
		"cipher_text": base64.StdEncoding.EncodeToString(ciphertext),
	}

	fmt.Println("NEW NONCE", result["nonce"])
	fmt.Println("New cipher", result["cipher_text"])
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

	serverConnConfig, err := tryToStartTCPServer(IPv4Address, 3000, 3010, keyPair.PrivateKey)
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

// dodalem szyfrowanie AES + RSA
// w tym momencie dziala wymiana kluczy za pomoca RSA a nastepnie jest wysylana wiadomosc z komenda "siema"
// i wtedy ona jest rozczytywana i mozna sobie normalnie odczytać tą wiadomość i jakoś coś zrobić :D
// teraz ogarnac to do konca - kazda komenda z szyfrowaniem
// dodac wlaczanie i wylacznie gry
// dodac zapisywanie wynikow
// dodac generowanie jedzonka z serwera podczas gry
// dodac mozliwosc pobierania statystyk
// dodac mozliwosc logowania
// dodac mozliwosc rejestrowania sie
