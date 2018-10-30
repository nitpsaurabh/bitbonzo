package encrypt_decrypt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
)

//encrypt
func Encrypt(text string) (cypherText string, err error) {
	var hash []byte
	if hash, err = bcrypt.GenerateFromPassword([]byte(text),
		bcrypt.MinCost); err == nil {
		cypherText = string(hash)
	} else {
		fmt.Println("err", err)
	}
	return
}

//ComparePassword
func ComparePassword(hashedPwd string, plainPwd string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPwd),
		[]byte(plainPwd)); err != nil {
		log.Println(err)
		return false
	}
	return true
}

//GenerateRandomBytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

//GenerateRandomString for session key or other stuff
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

//func Decrypt(text string)
