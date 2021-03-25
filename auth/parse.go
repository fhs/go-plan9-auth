package auth

import "encoding/binary"

func gbytes(p []byte) ([]byte, []byte) {
	if p == nil || len(p) < 2 {
		return nil, p
	}
	n := binary.LittleEndian.Uint16(p)
	p = p[2:]
	if len(p) < int(n) {
		return nil, p
	}
	return p[:n], p[n:]
}

func gstring(p []byte) (string, []byte) {
	s, p := gbytes(p)
	if s == nil {
		return "", p
	}
	return string(s), p
}

// Info is the AuthInfo structure returned after a successful authentication.
type Info struct {
	cuid   string // caller id
	suid   string // server id
	cap    string // capability (only valid on server side)
	secret []byte // secret
}

func convM2AI(p []byte) (*Info, []byte) {
	ai := new(Info)
	ai.cuid, p = gstring(p)
	ai.suid, p = gstring(p)
	ai.cap, p = gstring(p)
	ai.secret, p = gbytes(p)
	if p == nil {
		return nil, p
	}
	return ai, p
}
