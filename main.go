package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

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

// encrypt string aes256
// https://gist.github.com/donvito/efb2c643b724cf6ff453da84985281f8
func encryptWithPassword(stringToEncrypt string, keyString string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := b64.StdEncoding.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%s", ciphertext)
}

// decrypt string aes256
func decryptWithPassword(encryptedString string, keyString string) (decryptedString string) {

	key, _ := b64.StdEncoding.DecodeString(keyString)
	enc, _ := b64.StdEncoding.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return string(plaintext[:])
}

func toHex(InputString string) string {
	return hex.EncodeToString([]byte(InputString))
}

func generateKyber() string {
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
	return b64.StdEncoding.EncodeToString([]byte(secretKey))
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
	app.Get("generatekyber", h_generatekyber)
	app.Post("/encryptwithpass", h_encryptwithpass)
	app.Post("/decryptwithpass", h_decryptwithpass)

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

func h_generatekyber(c *fiber.Ctx) error {
	return c.SendString(generateKyber())
}

func h_encryptwithpass(c *fiber.Ctx) error {
	s := strings.Split(string(c.Body()), ";")
	plaintext_body := s[0]
	//fmt.Println(plaintext_body) //DEBUG
	decoded_b64 := s[1]
	return c.SendString(b64.StdEncoding.EncodeToString([]byte(encryptWithPassword(plaintext_body, string(decoded_b64)))))
}

func h_decryptwithpass(c *fiber.Ctx) error {
	s := strings.Split(string(c.Body()), ";")
	cipherbody_body := s[0]
	decoded_b64 := s[1]
	return c.SendString(decryptWithPassword(cipherbody_body, string(decoded_b64)))
}
