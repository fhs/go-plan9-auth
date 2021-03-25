// Copyright 2012 The go-plan9-auth Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package auth provides routines to authenticate users
// on Plan 9 and related systems.
package auth

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fhs/9fans-go/plan9"
	"github.com/fhs/9fans-go/plan9/client"
)

const (
	rpcMaxLen = 4096
)

// A Status represents a RPC reply type.
type Status string

// These are the possible reply types from a RPC.
const (
	StatusBadKey   Status = "badkey"
	StatusDone     Status = "done"
	StatusError    Status = "error"
	StatusNeedKey  Status = "needkey"
	StatusOK       Status = "ok"
	StatusPhase    Status = "phase"
	StatusTooSmall Status = "toosmall"
)

var rpcReplyStatuses = []Status{
	StatusBadKey,
	StatusDone,
	StatusError,
	StatusNeedKey,
	StatusOK,
	StatusPhase,
	StatusTooSmall,
}

// RPC represents an opened factotum(4) rpc file.
type RPC struct {
	f   *client.Fid
	buf [rpcMaxLen]byte
}

// NewRPC creates and returns a new RPC.
func NewRPC() (*RPC, error) {
	fsys, err := mountFactotum()
	if err != nil {
		return nil, err
	}
	fid, err := fsys.Open("rpc", plan9.ORDWR)
	if err != nil {
		return nil, err
	}
	return &RPC{f: fid}, nil
}

// Close closes the underlying rpc file.
func (rpc *RPC) Close() error {
	return rpc.f.Close()
}

// Call sends a RPC request to factotum and returns the response.
func (rpc *RPC) Call(verb string, arg []byte) (Status, []byte, error) {
	if len(verb)+1+len(arg) > rpcMaxLen {
		return "", nil, errors.New("request too big")
	}
	i := copy(rpc.buf[:], []byte(verb))
	i += copy(rpc.buf[i:], []byte{' '})
	i += copy(rpc.buf[i:], arg)
	if _, err := rpc.f.Write(rpc.buf[:i]); err != nil {
		return "", nil, err
	}
	n, err := rpc.f.Read(rpc.buf[:])
	if err != nil {
		return "", nil, err
	}
	b := rpc.buf[:n]
	for _, s := range rpcReplyStatuses {
		ns := len(s)
		if bytes.HasPrefix(b, []byte(s)) {
			if len(b) == ns {
				return s, nil, nil
			}
			if b[ns] == ' ' {
				return s, b[ns+1:], nil
			}
		}
	}
	return "", nil, errors.New("bad rpc response: " + string(b))
}

// CallNeedKey is similar to Call except if the key involved
// is missing or incomplete, getKey is called in an attempt
// to obtain missing information.
func (rpc *RPC) callNeedKey(getKey GetKeyFunc, verb string, arg []byte) (Status, []byte, error) {
	for {
		status, b, err := rpc.Call(verb, arg)
		if err != nil {
			return status, b, err
		}
		switch status {
		default:
			return status, b, err
		case "needkey", "badkey":
			if getKey == nil {
				return status, b, errors.New("key not found")
			}
			if err := getKey(string(b)); err != nil {
				return status, b, err
			}
		}
	}
}

// GetUserPassword returns the username and password for the key
// formatted using format and a. GetKey is called to obtain missing
// information (if any).
func GetUserPassword(getKey GetKeyFunc, format string, a ...interface{}) (string, string, error) {
	rpc, err := NewRPC()
	if err != nil {
		return "", "", err
	}
	defer rpc.Close()
	status, _, err := rpc.callNeedKey(getKey, "start", []byte(fmt.Sprintf(format, a...)))
	if status != "ok" {
		return "", "", fmt.Errorf("rpc start failed: %v", err)
	}
	status, b, err := rpc.callNeedKey(getKey, "read", nil)
	if status != "ok" {
		return "", "", fmt.Errorf("rpc read failed: %v", err)
	}
	up := tokenize(string(b), 2)
	if len(up) != 2 {
		return "", "", fmt.Errorf("bad factotum rpc response: %v", up)
	}
	return up[0], up[1], nil
}
