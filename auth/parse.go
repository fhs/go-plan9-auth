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
	CallerID string // caller id
	ServerID string // server id
	Cap      string // capability (only valid on server side)
	Secret   []byte // secret
}

func convM2AI(p []byte) (*Info, []byte) {
	ai := new(Info)
	ai.CallerID, p = gstring(p)
	ai.ServerID, p = gstring(p)
	ai.Cap, p = gstring(p)
	ai.Secret, p = gbytes(p)
	if p == nil {
		return nil, p
	}
	return ai, p
}
