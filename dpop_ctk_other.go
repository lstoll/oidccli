//go:build !darwin

package main

import (
	"fmt"

	"lds.li/oauth2ext/clitoken"
	"lds.li/oauth2ext/dpop"
)

func newDPoPSigner(label string) (*dpop.Signer, error) {
	if label != "" {
		return nil, fmt.Errorf("--dpop-ctk-label %q is only supported on macOS", label)
	}
	dpopSigner, err := dpop.NewSigner(clitoken.BestSigner())
	if err != nil {
		return nil, fmt.Errorf("creating dpop signer: %w", err)
	}
	return dpopSigner, nil
}
