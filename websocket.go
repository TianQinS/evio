package evio

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"unsafe"
)

const (
	wordSize = int(unsafe.Sizeof(uintptr(0)))
)

var (
	keyGUID = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
)

func computeAcceptKey(challengeKey string) string {
	h := sha1.New()
	challengeKey = strings.TrimSpace(challengeKey)
	h.Write([]byte(challengeKey))
	h.Write(keyGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func parseHeader(shake string) map[string]string {
	header := make(map[string]string)
	shake = strings.ReplaceAll(shake, "\r\n", "$$")
	shake = strings.ReplaceAll(shake, "\r\r", "$$")
	shake = strings.ReplaceAll(shake, "\r", "$$")
	shakes := strings.Split(shake, "$$")[1:]
	for _, line := range shakes {
		if strings.Contains(line, ":") {
			lines := strings.SplitN(line, ":", 2)
			header[lines[0]] = lines[1]
		}
	}
	return header
}

// Hankshake process websocket handshake protocol.
func Handshake(con net.Conn) (err error) {
	var n int
	var packet [0xFFFF]byte
	if n, err = con.Read(packet[:]); err != nil {
		return
	}
	header := parseHeader(string(packet[:n]))
	if key, ok := header["Sec-WebSocket-Key"]; !ok {
		err = fmt.Errorf("Sec-WebSocket-Key not found")
	} else {
		szOrigin := strings.TrimSpace(header["Origin"])
		szKey := computeAcceptKey(key)
		szHost := strings.TrimSpace(header["Host"])
		szProt := ""
		szProtocol := strings.TrimSpace(header["Sec-Websocket-Protocol"])
		if szProtocol != "" {
			protocols := strings.Split(szProtocol, ",")
			if len(protocols) > 0 {
				szProt = fmt.Sprintf("Sec-WebSocket-Protocol: %s\r\n", strings.TrimSpace(protocols[0]))
			}
		}
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%sWebSocket-Origin: %s\r\nWebSocket-Location: ws://%s/\r\n\r\n"
		resp = fmt.Sprintf(resp, szKey, szProt, szOrigin, szHost)
		con.Write([]byte(resp))
	}
	return
}
