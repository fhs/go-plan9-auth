package auth

import (
	"github.com/fhs/9fans-go/plan9/client"
)

func mountFactotum() (*client.Fsys, error) {
	return &client.Fsys{Mtpt: "/mnt/factotum"}, nil
}
