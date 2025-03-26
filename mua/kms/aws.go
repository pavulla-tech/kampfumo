package main

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type AWSKMS struct {
	client *kms.Client
	keyARN string
}

// NewAWSKMS creates a configured KMS client
func NewAWSKMS(ctx context.Context, region, keyARN string) (*AWSKMS, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	return &AWSKMS{
		client: kms.NewFromConfig(cfg),
		keyARN: keyARN,
	}, nil
}

// EncryptForStorage implements KMS encryption
func (a *AWSKMS) EncryptForStorage(data []byte) ([]byte, []byte, error) {
	result, err := a.client.Encrypt(context.TODO(), &kms.EncryptInput{
		KeyId:               aws.String(a.keyARN),
		Plaintext:           data,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return nil, nil, err
	}
	return result.CiphertextBlob, nil, nil
}

// DecryptFromStorage implements KMS decryption
func (a *AWSKMS) DecryptFromStorage(ciphertext []byte, _ []byte) ([]byte, error) {
	result, err := a.client.Decrypt(context.TODO(), &kms.DecryptInput{
		CiphertextBlob: ciphertext,
		KeyId:          aws.String(a.keyARN),
	})
	if err != nil {
		return nil, err
	}
	return result.Plaintext, nil
}
