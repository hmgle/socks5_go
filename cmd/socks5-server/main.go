package main

import (
	"flag"

	"github.com/hmgle/socks5_go"
)

func main() {
	var port string
	flag.StringVar(&port, "port", ":1984", ":port listen on")
	flag.Parse()

	s := socks5.NewServer(port)
	s.Start()
}
