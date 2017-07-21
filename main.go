package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/satori/go.uuid"
)

var (
	privateKey *rsa.PrivateKey
	nodeId     uuid.UUID
)

func init() {
	var err error

	nodeId = uuid.NewV1()
	log.Println(fmt.Sprintf("Node id: %s", nodeId.String()))

	log.Println("Generating rsa key pair...")
	privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {

}
