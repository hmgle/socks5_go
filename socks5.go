package socks5

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/hmgle/tcfs-go"
)

const (
	socks5Version = uint8(5)
)

const (
	ipv4Address = uint8(1)
	fqdnAddress = uint8(3)
	ipv6Address = uint8(4)
)

var (
	errBadAddrType = fmt.Errorf("Unrecognized address type")
)

// AddrSpec is used to return the target AddrSpec
type AddrSpec struct {
	Addr string
	Port int
}

type Local struct {
	faddr, baddr *net.TCPAddr
	cipher       *tcfs.Cipher
}

type Server struct {
	server *net.TCPAddr
	cipher *tcfs.Cipher
}

func NewLocal(faddr, baddr string, cryptoMethod string, key []byte) *Local {
	a1, err := net.ResolveTCPAddr("tcp", faddr)
	if err != nil {
		log.Fatalln("resolve frontend error:", err)
	}
	a2, err := net.ResolveTCPAddr("tcp", baddr)
	if err != nil {
		log.Fatalln("resolve backend error:", err)
	}
	var cipher *tcfs.Cipher
	if len(key) > 0 {
		cipher = tcfs.NewCipher(cryptoMethod, key)
	}
	return &Local{a1, a2, cipher}
}

func NewServer(port string, cryptoMethod string, key []byte) *Server {
	addr, err := net.ResolveTCPAddr("tcp", port)
	if err != nil {
		log.Fatalln("resolve frontend error:", err)
	}
	var cipher *tcfs.Cipher
	if len(key) > 0 {
		cipher = tcfs.NewCipher(cryptoMethod, key)
	}
	return &Server{addr, cipher}
}

func (s *Local) Start() {
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

func (s *Local) handleConn(conn net.Conn) error {
	bufConn := bufio.NewReader(conn)

	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		log.Println("read:", err)
		return err
	}
	if version[0] != socks5Version {
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
	lConn := NewConn(conn, nil)
	sConn := NewConn(backConn, s.cipher)
	go pipe(sConn, lConn)
	go pipe(lConn, sConn)
	return nil
}

func (s *Server) Start() {
	ln, err := net.ListenTCP("tcp", s.server)
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

func (s *Server) handleConn(conn net.Conn) error {
	cConn := NewConn(conn, s.cipher)
	bufConn := bufio.NewReader(cConn)

	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		log.Println("io.ReadAtLeast:", err)
		return fmt.Errorf("Failed to get command version: %v", err)
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		log.Println("bad version")
		return fmt.Errorf("Unsupported command version: %v", header[0])
	}

	// Read in the destination address
	dest, err := readAddrSpec(bufConn)
	if err != nil {
		log.Println("bad addr")
		return fmt.Errorf("Failed to read dest addr: %v", err)
	}
	cConn.Write([]byte{0x05, 0, 0, 0x01, 0, 0, 0, 0, 0x19, 0x19})
	remote, err := net.Dial("tcp", fmt.Sprintf("%s:%d", dest.Addr, dest.Port))
	if err != nil {
		log.Println("net.Dial failed:", dest.Addr, dest.Port)
		return err
	}

	rConn := NewConn(remote, nil)
	go pipe(rConn, cConn)
	go pipe(cConn, rConn)
	return nil
}

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.Addr = net.IP(addr).String()
	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.Addr = net.IP(addr).String()
	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.Addr = string(fqdn)
	default:
		return nil, errBadAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

func pipe(dst, src *Conn) {
	for {
		_, err := io.Copy(dst, src)
		if err != nil {
			return
		}
	}
}
