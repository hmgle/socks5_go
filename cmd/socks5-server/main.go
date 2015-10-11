package main

import (
	"flag"

	"github.com/hmgle/socks5_go"
)

func main() {
	var port, cryptoMethod, key string
	flag.StringVar(&port, "port", ":1984", ":port listen on")
	flag.StringVar(&cryptoMethod, "crypto", "rc4", "encryption method")
	flag.StringVar(&key, "key", "", "password used to encrypt the data")
	flag.Parse()

	s := socks5.NewServer(port, cryptoMethod, []byte(key))
	s.Start()
}
