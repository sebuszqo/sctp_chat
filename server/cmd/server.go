package main

import (
	"fmt"
	"log"
	"snake_network_game/server"
	"sync"
	"time"
)

func main() {
	log.Println("Starting game server ...")
	log.Println("Generating RSA key pair.")
	keyPair, err := server.GenerateKeyPair(2048)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("RSA key pair generated.")

	log.Println("Setting Server's IP and Port.")
	IPv4Address, err := server.GetLocalIP()
	if err != nil {
		log.Fatalln(err.Error())
	}
	minPort := 3000
	maxPort := 3010

	log.Println(fmt.Printf("Starting TCP server on IP: %s and Port between: %d and %d \n", IPv4Address, minPort, maxPort))
	serverConnConfig, err := server.TryToStartTCPServer(IPv4Address, minPort, maxPort, keyPair.PrivateKey)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println(fmt.Printf("TCP started on IP: %s and Port: %s \n", serverConnConfig.IP, serverConnConfig.Port))

	publicKey := server.PublicKeyToBytes(keyPair.PublicKey)

	gameType := server.Snake
	srv := server.ServerInfo{
		Name:      "Game Server",
		GameType:  gameType,
		TCPConn:   serverConnConfig,
		PublicKey: string(publicKey),
		Command:   server.Start,
	}

	log.Println("Configuring UDP multicast server.")
	serverInfo, conn, err := server.ConfigureUDP(srv)
	if err != nil {
		log.Fatal(err.Error())
	}

	const maxAttempts = 5
	attemptCount := 0
	sendMulticastFor := 10000 * time.Second

	var multicastWaitGroup sync.WaitGroup

	for attemptCount < maxAttempts {
		multicastDoneChan := make(chan bool, 1)
		multicastErrorChan := make(chan error, 1)

		multicastWaitGroup.Add(1)
		log.Println("Start sending multicast ServerInfor messages")
		go server.SendMulticast(server.MulticastGroup, serverInfo, conn, 1*time.Second, multicastDoneChan, multicastErrorChan, &multicastWaitGroup)

		select {
		case err := <-multicastErrorChan:
			log.Printf("Received multicast error: %s\n", err)
			attemptCount++
			log.Printf("Retrying... Attempt %d of %d\n", attemptCount, maxAttempts)
			multicastWaitGroup.Wait()
			continue
		case <-time.After(sendMulticastFor):
			close(multicastDoneChan)
			multicastWaitGroup.Wait()
			fmt.Println("Multicast period completed without errors")
			return
		}
	}

	log.Println("More than 5 attempts to restart multicast, closing app...")
}
