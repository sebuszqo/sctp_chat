package server

import (
	"crypto/rsa"
	"encoding/json"
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

type GameType string

const (
	Snake     GameType = "snake"
	TicTacToe GameType = "ticTacToe"
)

type ServerConnection struct {
	IP   string
	Port string
}

type KeyPair struct {
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Game struct {
	Score int    `json:"score"`
	Level int    `json:"level"`
	Time  string `json:"time"`
}

type HighScore struct {
	Username string `json:"username"`
	Score    int    `json:"score"`
}

type MulticastError struct {
	Msg string
}

func (e *MulticastError) Error() string {
	return e.Msg
}
