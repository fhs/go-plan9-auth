// Copyright 2020 The go-plan9-auth Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !plan9

package auth

import (
	"9fans.net/go/plan9/client"
)

func mountFactotum() (*client.Fsys, error) {
	return client.MountService("factotum")
}
