package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"triple-pci-service/mua"
)

func loadPrivateKeyFromEnv() (*rsa.PrivateKey, error) {
	privateKeyBase64 := os.Getenv("PRIVATE_KEY_BASE64")
	if privateKeyBase64 == "" {
		return nil, errors.New("env PRIVATE_KEY_BASE64 não definida")
	}

	// Decodificar Base64 para PEM
	pemBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("formato PEM inválido")
	}

	// Se a chave estiver encriptada com senha (opcional)
	if x509.IsEncryptedPEMBlock(block) {
		decryptedBlock, err := x509.DecryptPEMBlock(block, []byte(os.Getenv("PRIVATE_KEY_PASSWORD")))
		if err != nil {
			return nil, err
		}
		return x509.ParsePKCS1PrivateKey(decryptedBlock)
	}

	// Para chaves PKCS#8 (formato padrão do OpenSSL)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key.(*rsa.PrivateKey), nil
}

// Exemplo de uso:
func main() {

	privateKey, err := loadPrivateKeyFromEnv()
	if err != nil {
		panic(err)
	}

	// Simulação de dados do cliente (substitua com dados reais)
	encryptedSessionKey, _ := hex.DecodeString("b938cfcd9fc302c773e82e5573765842d505be94c24852209477cef10437dac9038256a8d6937f733b10c862eb5fb21e30b571fabe9fb345b8f8bab178aaa0802c915a2f047b641ab018e9f5f70c554d56ac19a12e915437a066ca41b9073b086a80f51944dd478ea2b199946a0a3a43bc00b32817d4dd70351fd9bf3281b5e14a680069c6c4ee6cb21b58db5902283ef2a3cb93ef21431cc4b9368e21ef90442362e611aa695230efb87f64d1dc42388f02d7f052fe61a808ef764763737ea70169afcd4dbbebf8970c7d616c376ab0863326ab1136aef8baf40b96ff2a3228c5e277869ccaac8758f2fd6d9a4cab36c34bd2ad4dd346ed0fd6a7a8a12b90276782c600b37fb03d59e3d098a0cedb6485b2c6a9a4dd2ffd9960734702fdc2e7ec6c8ee6dd2bd94255980b012f86b66edf2f6bea229918a152b8cfefa2e3d55162798e3d44a35129979716b3e1411b8fa2e8ab5ceceddbe3b8b096a42fb9ea33ba6b1eca2450b16d977724773ed7114530eeeb6093a7399a7854db5580b4ce22") // Cole aqui o valor real do cliente
	encryptedData, _ := hex.DecodeString("b278032f94f6fcce2c00485c05272390d3389c146fe3f033e46f4e2851")                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             // Cole aqui o valor real do cliente
	nonce, _ := hex.DecodeString("e20d9b9399f205ef77d53f8d")                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       // Deve ter 12 bytes

	sessionKey, err := mua.DecryptSessionKey(encryptedSessionKey, privateKey)
	if err != nil {
		panic(fmt.Sprintf("Falha ao descriptar chave de sessão: %v", err))
	}

	decryptedData, err := mua.DecryptDataForUsage(encryptedData, nonce, sessionKey)
	if err != nil {
		panic(fmt.Sprintf("Falha ao descriptar dados: %v", err))
	}

	fmt.Printf("Dados descriptados: %s\n", decryptedData)

	//Storage Related
	mua := mua.NewMockKMS()

	// Dados simulados (em produção, busque do banco de dados)
	//  encryptedData := []byte{...} // Ex: valor encriptado salvo no armazenamento
	encryptedDataForStorage, storageNonce, err := mua.EncryptForStorage([]byte(decryptedData)) // Indica aqui o data a encriptar
	// nonce := []byte{...}         // Nonce salvo junto com os dados

	if err != nil {
		panic(err)
	}

	fmt.Printf("Dados encriptados: %s\n", encryptedDataForStorage)
	fmt.Printf("Nonce de gravacao: %s\n", storageNonce)

	decryptedDataFromStorage, err := mua.DecryptFromStorage(encryptedDataForStorage, storageNonce)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Dados da base de descriptados: %s\n", decryptedDataFromStorage)

}
