package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Carregar chave pública de variável de ambiente (Base64)
func loadPublicKeyFromEnv() (*rsa.PublicKey, error) {
	publicKeyBase64 := os.Getenv("PUBLIC_KEY_BASE64")
	if publicKeyBase64 == "" {
		return nil, errors.New("env PUBLIC_KEY_BASE64 não definida")
	}

	// Decodificar Base64 para PEM
	pemBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("formato PEM inválido")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}

// Gerar chave AES-256 para a sessão
func generateSessionKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encriptar dados com AES-GCM
func encryptData(data []byte, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	encrypted := gcm.Seal(nil, nonce, data, nil)
	return encrypted, nonce, nil
}

// Encriptar chave de sessão com RSA (chave pública do backend)
func encryptSessionKey(sessionKey []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	encryptedSessionKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		sessionKey,
		nil, // Label (deixe vazio)
	)
	return encryptedSessionKey, err
}

// Carregar chave pública do backend
// func loadPublicKey(path string) (*rsa.PublicKey, error) {
// 	pemData, err := os.ReadFile(path)
// 	if err != nil {
// 		return nil, err
// 	}

// 	block, _ := pem.Decode(pemData)
// 	if block == nil {
// 		return nil, errors.New("failed to parse PEM block")
// 	}

// 	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return pub.(*rsa.PublicKey), nil
// }

// Exemplo de uso:
func main() {
	//publicKey, _ := loadPublicKey("../keys/public.pem")
	publicKey, err := loadPublicKeyFromEnv()
	if err != nil {
		panic(err)
	}
	sessionKey, _ := generateSessionKey() // 32 bytes!
	data := []byte("Helton Assane")

	encryptedData, nonce, _ := encryptData(data, sessionKey)
	encryptedSessionKey, _ := encryptSessionKey(sessionKey, publicKey)

	fmt.Printf("Encrypted Session Key (hex): %x\n", encryptedSessionKey)
	fmt.Printf("Nonce (hex): %x\n", nonce)
	fmt.Printf("Encrypted Data: %x\n", encryptedData)

}
