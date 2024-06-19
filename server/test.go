package server

// import (
// 	"crypto/aes"
// 	"crypto/cipher"
// 	"crypto/rand"
// 	"encoding/base64"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"log"
// )

// func DecryptAES(key []byte, nonceB64 string, ciphertextB64 string) ([]byte, error) {
// 	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
// 	if err != nil {
// 		return nil, err
// 	}

// 	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
// 	if err != nil {
// 		return nil, err
// 	}

// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Ensure nonce length is appropriate
// 	if len(nonce) != 8 {
// 		return nil, fmt.Errorf("nonce length must be 8 bytes, got %d bytes", len(nonce))
// 	}

// 	// Create a 16-byte IV for AES-CTR
// 	iv := make([]byte, aes.BlockSize)
// 	copy(iv, nonce)

// 	stream := cipher.NewCTR(block, iv)
// 	plaintext := make([]byte, len(ciphertext))
// 	stream.XORKeyStream(plaintext, ciphertext)

// 	return plaintext, nil
// }

// // EncryptAES encrypts data using AES in CTR mode.
// func EncryptAES(key, data []byte) (string, error) {
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return "", err
// 	}

// 	nonce := make([]byte, block.BlockSize())
// 	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
// 		return "", err
// 	}

// 	stream := cipher.NewCTR(block, nonce)
// 	ciphertext := make([]byte, len(data))
// 	stream.XORKeyStream(ciphertext, data)

// 	result := map[string]string{
// 		"nonce":      base64.StdEncoding.EncodeToString(nonce),
// 		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
// 	}

// 	jsonData, err := json.Marshal(result)
// 	if err != nil {
// 		return "", err
// 	}

// 	return string(jsonData), nil
// }

// func main() {
// 	// key := make([]byte, 16)
// 	// if _, err := rand.Read(key); err != nil {
// 	// 	panic(err)
// 	// }
// 	// fmt.Printf("Key: %x\n", key)

// 	// data := []byte("this is a secret message")

// 	// encrypted, err := EncryptAES(key, data)
// 	// if err != nil {
// 	// 	panic(err)
// 	// }
// 	// fmt.Printf("Encrypted: %s\n", encrypted)
// 	encodedKey := "Kzgwz58DT3EvZTeQW95rs9sHfqD+FONqIVTHswV6O3M="
// 	key, err := base64.StdEncoding.DecodeString(encodedKey)
// 	if err != nil {
// 		fmt.Println("Error decoding key:", err)
// 		return
// 	}
// 	// jsonData := `{"nonce": "uvRYMeTnDSQ=", "ciphertext": "AVyfi3W4XLYgCoEg/UwNC2ykoBClrorSxWPZwoTxrEnpqpRCM5XO2mSGwFlR6+cwcBLbVWyhHgTI4QeDkIlydP8+JcieDREurDMTLlKn2AGNROsUO8LGtcMmMg=="}`

// 	decrypted, err := DecryptAES(key, "0Y9H7Fpk++8=", "DskJJMOWvMY='")
// 	if err != nil {
// 		log.Fatalln("ERRRR", err)
// 	}
// 	fmt.Printf("Decrypted: %s\n", decrypted)
// }
