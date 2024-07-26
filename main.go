package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"log"

	kyberk2so "github.com/symbolicsoft/kyber-k2so"

	b64 "encoding/base64"

	"github.com/gofiber/fiber/v2"
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

func toHex(InputString string) string {
	return hex.EncodeToString([]byte(InputString))
}

func main() {
	//Krystal Kyber
	privateKey, publicKey, _ := kyberk2so.KemKeypair1024()
	ciphertext, ssA, _ := kyberk2so.KemEncrypt1024(publicKey)
	ssB, _ := kyberk2so.KemDecrypt1024(ciphertext, privateKey)

	fmt.Printf("Hex ssA: %s\n", toHex(string(ssA[:])))
	fmt.Printf("ssA: %s\n", string(ssA[:]))
	fmt.Printf("Hex ssB: %s\n", toHex(string(ssB[:])))
	fmt.Printf("ssB: %s\n", string(ssB[:]))

	//SecretKey
	secretKey = string(ssA[:])
	fmt.Printf("SecretKey Base64: %s\n", b64.StdEncoding.EncodeToString([]byte(secretKey)))

	// Fiber instance
	app := fiber.New()

	// Routes
	app.Get("/secretkey", h_secretkey)
	app.Post("/encrypt", h_encrypt)
	app.Post("/decrypt", h_decrypt)

	// Start server
	log.Fatal(app.Listen(":3000"))
}

// Handlers
func h_secretkey(c *fiber.Ctx) error {
	return c.SendString(b64.StdEncoding.EncodeToString([]byte(secretKey)))
}

func h_encrypt(c *fiber.Ctx) error {
	return c.SendString(b64.StdEncoding.EncodeToString([]byte(encrypt(string(c.Body())))))
}

func h_decrypt(c *fiber.Ctx) error {
	decoded_b64, err := b64.StdEncoding.DecodeString(string(c.Body()))
	if err != nil {
		return c.SendString(err.Error())
	} else {
		return c.SendString(decrypt(string(decoded_b64)))
	}
}