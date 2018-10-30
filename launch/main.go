package main

import (
	coinUser "coinmark/user/service"
	"github.com/rightjoin/aqua"
)

// main function
func main() {
	server := aqua.NewRestServer()
	server.AddService(&coinUser.User{})
	server.Run()
}
