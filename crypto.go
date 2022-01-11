package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

// See from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
const keyBytes = 32
const saltBytes = 8
const kdfIterationCount = 1000

func deriveKey(password_plain []byte, salt []byte) []byte {
	return pbkdf2.Key(password_plain, salt, kdfIterationCount, keyBytes, sha256.New)
}

func encrypt(password_plain []byte, salt []byte, plainText []byte) ([]byte, error) {
	key := deriveKey(password_plain, salt)

	cipher_, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(cipher_)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	cipherText := gcm.Seal(nonce, nonce, plainText, nil)
	return cipherText, nil
}

func decrypt(password_plain []byte, salt []byte, cipherText []byte) ([]byte, error) {
	key := deriveKey(password_plain, salt)

	cipher_, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(cipher_)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
