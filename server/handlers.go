package server

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"syscall"
	"time"
)

func HandleRegister(connFd int, msg Message) {
	var payload RegisterRequest
	jsonPayload, _ := json.Marshal(msg.Payload)
	json.Unmarshal(jsonPayload, &payload)
	// log.Printf("DECRYPTED PAYLOAD: %+v", payload)
	response := RegisterResponse{
		Success: true,
		Message: "Registration successful",
	}
	jsonResponse, _ := json.Marshal(Message{
		Command: "register_response",
		Payload: response,
	})
	log.Println("Sending response for Register Request")
	syscall.Write(connFd, jsonResponse)
}

func HandleLogin(connFd int, decodedAES []byte, ciphertext []byte, logged *bool, userName *string) {
	var payload DefaultRequest
	json.Unmarshal(ciphertext, &payload)
	aesKey, _ := base64.StdEncoding.DecodeString(string(decodedAES))
	decrypted, err := DecryptAES(aesKey, payload.Nonce, payload.CipherText)
	if err != nil {
		log.Fatalln("Error during AES decryption:", err)
	}
	var incomingUser User
	json.Unmarshal(decrypted, &incomingUser)
	fmt.Println("Decrypted data:", string(decrypted))
	for login, user := range users {
		if login == incomingUser.Username && user.Password == incomingUser.Password {
			*logged = true
			fmt.Printf("USER: %s logged \n", login)
			*userName = incomingUser.Username
		}
	}
	data, err := json.Marshal(LoginResponse{
		Success: *logged,
	})

	if err != nil {
		log.Fatalln("ERROR DURING MARSHALING", err)
	}
	encyrption, err := EncryptAES(aesKey, data)
	if err != nil {
		log.Fatalln("ERRRR", err)
	}
	encrytedData := base64.StdEncoding.EncodeToString(encyrption)
	log.Println("Sending response for Login Request")
	syscall.Write(connFd, []byte(encrytedData))
}

func HandleNewGame(connFd int, msg Message, cipherText []byte, privPEM *rsa.PrivateKey, decodedAES []byte, userName string) {
	var payload DefaultRequest
	json.Unmarshal(cipherText, &payload)
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
	log.Println("Updating High Scores and Adding new Game to user's game list")

	UpdateHighScores(userName, score)

	AddGame(userName, score, level, time.Now().Format(time.RFC3339))

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
	log.Println("Sending response for New Game Request")
	syscall.Write(connFd, []byte(encrytedData))
}

func HandleViewHighScores(connFd int, decodedAES []byte) {
	aesKey, err := base64.StdEncoding.DecodeString(string(decodedAES))
	highScoresMutex.Lock()
	highScoresResponse := highScores
	highScoresMutex.Unlock()
	log.Println("CURRENT HIGH SCORE: ", highScoresResponse)

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
	log.Println("Sending response for View High Scores Request")
	syscall.Write(connFd, []byte(encryptedData))
}

func HandleViewLastGames(connFd int, decodedAES []byte, userName string) {
	aesKey, err := base64.StdEncoding.DecodeString(string(decodedAES))
	lastGames := ViewLastGames(userName)

	data, err := json.Marshal(ViewLastGamesResponse{
		LastGames: lastGames,
		Success:   true,
	})
	if err != nil {
		log.Fatalln("ERROR DURING MARSHALING", err)
	}
	encryption, err := EncryptAES(aesKey, data)
	if err != nil {
		log.Fatalln("Error during AES encryption:", err)
	}
	encryptedData := base64.StdEncoding.EncodeToString(encryption)
	log.Println("Sending response for View Last Games Request")
	syscall.Write(connFd, []byte(encryptedData))
}

func HandlePlayerMove(msg Message) {
	var payload PlayerMove
	jsonPayload, _ := json.Marshal(msg.Payload)
	json.Unmarshal(jsonPayload, &payload)
}
