package socks5

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
)

type Socks5Local struct {
	faddr, baddr *net.TCPAddr
}

func NewSocks5Local(faddr, baddr string) *Socks5Local {
	a1, err := net.ResolveTCPAddr("tcp", faddr)
	if err != nil {
		log.Fatalln("resolve frontend error:", err)
	}
	a2, err := net.ResolveTCPAddr("tcp", baddr)
	if err != nil {
		log.Fatalln("resolve backend error:", err)
	}
	return &Socks5Local{a1, a2}
}

func (s *Socks5Local) Start() {
	ln, err := net.ListenTCP("tcp", s.faddr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Socks5Local) handleConn(conn net.Conn) error {
	bufConn := bufio.NewReader(conn)

	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		log.Println("read:", err)
		return err
	}
	if version[0] != uint8(5) {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		log.Println("[ERR] socks: %v", err)
		return err
	}
	nmethods := []byte{0}
	if _, err := bufConn.Read(nmethods); err != nil {
		log.Println("read:", err)
		return err
	}
	numMethods := int(nmethods[0])
	_methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(bufConn, _methods, numMethods)
	if err != nil {
		log.Println("ReadAtLeast:", err)
		return err
	}
	conn.Write([]byte{0x05, 0x00})

	backConn, err := net.DialTCP("tcp", nil, s.baddr)
	if err != nil {
		log.Println(err)
		return err
	}
	go pipe(conn, backConn)
	go pipe(backConn, conn)
	return nil
}

func pipe(dst, src net.Conn) {
	for {
		_, err := io.Copy(dst, src)
		if err != nil {
			return
		}
	}
}
