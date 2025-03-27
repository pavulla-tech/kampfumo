package mua

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
)

type EncriptionClient struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewEncriptionClient(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *EncriptionClient {
	return &EncriptionClient{privateKey: privateKey, publicKey: publicKey}
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

func (c *EncriptionClient) EncriptDataForTransport(data []byte) (encryptedData []byte, nonce []byte, encryptedSessionKey []byte, err error) {
	sessionKey, err := generateSessionKey()
	if err != nil {
		return 
	}
	encryptedData, nonce, err = encryptData(data, sessionKey)
	if err != nil {
		return 
	}
	encryptedSessionKey, err = encryptSessionKey(sessionKey, c.publicKey)
	if err != nil {
		return 
	}

	err = nil

	return 
	
}

// Desencriptar chave de sessão com RSA (chave privada do backend)
func (c *EncriptionClient) DecryptSessionKey(encryptedSessionKey []byte) ([]byte, error) {
	sessionKey, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		c.privateKey,
		encryptedSessionKey,
		nil, // Label deve corresponder ao do cliente
	)
	return sessionKey, err
}

// Desencriptar dados com AES-GCM
func (c *EncriptionClient) DecryptDataForUsage(encryptedData, nonce, key []byte) ([]byte, error) {
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
