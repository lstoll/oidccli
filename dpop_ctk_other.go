//go:build !darwin

package main

import (
	"fmt"

	"lds.li/oauth2ext/dpop"
)

func dpopSignerFromCTK(label string) (*dpop.Signer, error) {
	return nil, fmt.Errorf("--dpop-ctk-label %q is only supported on macOS", label)
}
