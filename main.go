package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	filePath := flag.String("file", "", "The vault file to use")
	password := flag.String("password", "", "The password to use")
	passwordFile := flag.String("passwordFile", "", "Path to a file containing the password to use")
	flag.Parse()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	if *filePath == "" {
		flag.Usage()
		os.Exit(1)
	} else {
		if strings.HasPrefix(*filePath, "~") {
			*filePath = strings.Replace(*filePath, "~", homeDir, 1)
		}

		*filePath, err = filepath.Abs(*filePath)
		if err != nil {
			panic(err)
		}
	}

	if *password == "" && *passwordFile == "" {
		fmt.Println("Either a password or passwordFile must be specified")
		os.Exit(1)
	}

	if *passwordFile != "" {
		if strings.HasPrefix(*passwordFile, "~") {
			*passwordFile = strings.Replace(*passwordFile, "~", homeDir, 1)
		}

		*passwordFile, err = filepath.Abs(*passwordFile)
		if err != nil {
			panic(err)
		}

		passwordBytes, err := os.ReadFile(*passwordFile)
		if err != nil {
			fmt.Printf("Error reading password file '%s'\n", *passwordFile)
			os.Exit(1)
		}
		*password = strings.TrimSpace(string(passwordBytes))
	}

	vault := NewPasswordVault(*filePath)
	vaultData := make(map[string]string)

	for _, arg := range flag.Args() {
		parts := strings.Split(arg, "=")
		if len(parts) != 2 {
			fmt.Printf("Set keys using the syntax key=value\n")
			os.Exit(1)
		}
		vaultData[parts[0]] = parts[1]
	}

	if flag.NArg() > 0 {
		err := vault.Save(*password, &vaultData)
		if err != nil {
			panic(err)
		}
	}

	vaultDataDecrypted, err := vault.Load(*password)
	if err != nil {
		panic(err)
	}

	prettyPrinter := json.NewEncoder(os.Stdout)
	prettyPrinter.SetIndent("", "  ")
	prettyPrinter.Encode(vaultDataDecrypted)
}
