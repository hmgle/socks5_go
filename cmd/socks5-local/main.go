package main

import (
	"flag"

	"github.com/hmgle/socks5_go"
)

func main() {
	var faddr, baddr, cryptoMethod, key string
	flag.StringVar(&faddr, "listen", ":2080", "host:port listen on")
	flag.StringVar(&baddr, "backend", "127.0.0.1:1984", "host:port of backend")
	flag.StringVar(&cryptoMethod, "crypto", "rc4", "encryption method")
	flag.StringVar(&key, "key", "", "password used to encrypt the data")
	flag.Parse()

	l := socks5.NewLocal(faddr, baddr, cryptoMethod, []byte(key))
	l.Start()
}
