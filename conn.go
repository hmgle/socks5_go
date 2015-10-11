package socks5

import (
	"net"
	"reflect"
)

type Cipher interface {
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

type Conn struct {
	conn   net.Conn
	cipher Cipher
}

func NewConn(conn net.Conn, cipher Cipher) *Conn {
	return &Conn{conn, cipher}
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.cipher == nil || reflect.ValueOf(c.cipher).IsNil() {
		return c.conn.Read(b)
	}
	n, err := c.conn.Read(b)
	if n > 0 {
		c.cipher.Decrypt(b[0:n], b[0:n])
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.cipher == nil || reflect.ValueOf(c.cipher).IsNil() {
		return c.conn.Write(b)
	}
	c.cipher.Encrypt(b, b)
	return c.conn.Write(b)
}

func (c *Conn) Close() {
	c.conn.Close()
}
