# Golang Port Sniffer C&C

Proof of concept, **don't** use this code on any machine that is not yours.

Inspired by [CIA Hive](https://thehackernews.com/2017/11/cia-hive-malware-code.html)

## Main :

Listens on the `interface` on the provided `port` socket, waiting to catch a specify `header` 
in order to execute the AES encrypted `command`.

The command is stored inside the `payload` section of the packet.

## Client :

Used to send an AES encrypted `command` with a specific `header` to a specific `port` for an IP address.

## How to use :

* clone the repo
* compile the server for the needed architecture
* compile the client
