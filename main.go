package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

		kyberk2so "github.com/symbolicsoft/kyber-k2so"

)

var (
	// We're using a 32 byte long secret key.
	// This is probably something you generate first
	// then put into and environment variable.
	secretKey string = ""
)

func encrypt(plaintext string) string {
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	// We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	// ciphertext here is actually nonce+ciphertext
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return string(ciphertext)
}

func decrypt(ciphertext string) string {
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	// Since we know the ciphertext is actually nonce+ciphertext
	// And len(nonce) == NonceSize(). We can separate the two.
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		panic(err)
	}

	return string(plaintext)
}

func main() {
	//Krystal Kyber

	privateKey, publicKey, _ := kyberk2so.KemKeypair1024()
	ciphertext, ssA, _ := kyberk2so.KemEncrypt1024(publicKey)
	ssB, _ := kyberk2so.KemDecrypt1024(ciphertext, privateKey)

	secretKey = string(ssA[:])
	fmt.Printf("ssA: %s \n", secretKey)
	
	// This will successfully encrypt & decrypt
	ciphertext1 := encrypt("This is some sensitive information")
	fmt.Printf("Encrypted ciphertext 1: %x \n", ciphertext1)

	plaintext1 := decrypt(ciphertext1)
	fmt.Printf("Decrypted plaintext 1: %s \n", plaintext1)

	// This will successfully encrypt & decrypt as well.
	ciphertext2 := encrypt("Hello")
	fmt.Printf("Encrypted ciphertext 2: %x \n", ciphertext2)

	plaintext2 := decrypt(ciphertext2)
	fmt.Printf("Decrypted plaintext 2: %s \n", plaintext2)

	secretKey = string(ssB[:])
	fmt.Printf("ssB: %s \n", secretKey)
	
	// This will successfully encrypt & decrypt
	ciphertext1 = encrypt("This is some sensitive information")
	fmt.Printf("Encrypted ciphertext 1: %x \n", ciphertext1)

	plaintext1 = decrypt(ciphertext1)
	fmt.Printf("Decrypted plaintext 1: %s \n", plaintext1)

	// This will successfully encrypt & decrypt as well.
	ciphertext2 = encrypt("Hello")
	fmt.Printf("Encrypted ciphertext 2: %x \n", ciphertext2)

	plaintext2 = decrypt(ciphertext2)
	fmt.Printf("Decrypted plaintext 2: %s \n", plaintext2)
}
