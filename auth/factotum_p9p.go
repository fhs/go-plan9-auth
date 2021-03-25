//go:build !plan9
// +build !plan9

package auth

import (
	"github.com/fhs/9fans-go/plan9/client"
)

func mountFactotum() (*client.Fsys, error) {
	return client.MountService("factotum")
}
