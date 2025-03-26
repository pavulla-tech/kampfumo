package mua

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
)

// Desencriptar chave de sessão com RSA (chave privada do backend)
func DecryptSessionKey(encryptedSessionKey []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	sessionKey, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		encryptedSessionKey,
		nil, // Label deve corresponder ao do cliente
	)
	return sessionKey, err
}

// Desencriptar dados com AES-GCM
func DecryptDataForUsage(encryptedData, nonce, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, encryptedData, nil)
}

// Simulação de KMS (usar AWS KMS, Google Cloud KMS em produção)
type MockKMS struct {
	storageKey []byte
}

func NewMockKMS() *MockKMS {
	key := make([]byte, 32)
	rand.Read(key) // Em produção, gere via KMS
	return &MockKMS{storageKey: key}
}

// Re-encriptar dados para armazenamento
func (kms *MockKMS) EncryptForStorage(data []byte) ([]byte, []byte, error) {
	block, _ := aes.NewCipher(kms.storageKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	encrypted := gcm.Seal(nil, nonce, data, nil)
	return encrypted, nonce, nil
}

// Recuperar chave de armazenamento (em produção, use APIs do KMS)
func (kms *MockKMS) GetStorageKey() []byte {
	return kms.storageKey
}

// Desencriptar dados do armazenamento
func (kms *MockKMS) DecryptFromStorage(encryptedData, nonce []byte) ([]byte, error) {
	key := kms.GetStorageKey()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, encryptedData, nil)
}
