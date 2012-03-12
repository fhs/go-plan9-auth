// Copyright 2012 The go-plan9-auth Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"fmt"
	"testing"
)

func TestGetUserPassword(t *testing.T) {
	user, pass := "gopher", "gorocks"
	params := "dom=testing.golang.org proto=pass role=client"
	key := params + fmt.Sprintf(" user=%s !password=%s", user, pass)

	ctl, err := newControl()
	if err != nil {
		t.Fatalf("open factotum/ctl: %v", err)
	}
	defer ctl.Close()
	if err := ctl.AddKey(key); err != nil {
		t.Fatalf("AddKey failed: %v\n", err)
	}

	user1, pass1, err := GetUserPassword(nil, params)
	if err != nil {
		t.Errorf("GetUserPassword failed: %v\n", err)
	}
	if user1 != user || pass1 != pass {
		t.Errorf("GetUserPassword gave user=%s !password=%s; want user=%s !password=%s\n", user1, pass1, user, pass)
	}

	if err := ctl.DeleteKey(params); err != nil {
		t.Errorf("DeleteKey failed: %v\n", err)
	}
}
