package main

import (
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/json"
	"os"
)

type PasswordVault struct {
	filePath string
}

func newSalt() ([]byte, error) {
	salt := make([]byte, saltBytes)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func NewPasswordVault(filePath string) *PasswordVault {
	vault := PasswordVault{
		filePath: filePath,
	}
	return &vault
}

func (vault *PasswordVault) Save(passwordPlain string, data *map[string]string) error {
	jsonStr, err := json.Marshal(data)
	if err != nil {
		return err
	}

	salt, err := newSalt()
	if err != nil {
		return err
	}

	cipherText, err := encrypt([]byte(passwordPlain), salt, jsonStr)
	if err != nil {
		return err
	}

	fileContents := append(salt, cipherText...)
	fileContentsB64 := b64.URLEncoding.EncodeToString(fileContents)

	file, err := os.Create(vault.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Pretty-print in case file is catted
	for idx, c := range fileContentsB64 {
		if idx > 0 && idx%80 == 0 {
			file.WriteString("\n")
		}
		file.WriteString(string(c))
	}

	file.WriteString("\n")
	file.Sync()

	return nil
}

func (vault *PasswordVault) Load(passwordPlain string) (*map[string]string, error) {
	fileContentsB64, err := os.ReadFile(vault.filePath)
	if err != nil {
		return nil, err
	}

	fileContents, err := b64.URLEncoding.DecodeString(string(fileContentsB64))
	if err != nil {
		return nil, err
	}

	salt, fileContents := fileContents[:saltBytes], fileContents[saltBytes:]
	plainText, err := decrypt([]byte(passwordPlain), salt, fileContents)
	if err != nil {
		return nil, err
	}

	data := make(map[string]string)
	err = json.Unmarshal(plainText, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}
