//go:build darwin

package main

import (
	"fmt"

	"lds.li/keychain"
	"lds.li/oauth2ext/dpop"
)

func dpopSignerFromCTK(label string) (*dpop.Signer, error) {
	identity, err := keychain.GetIdentity(keychain.IdentityQuery{
		Label: label,
		Type:  keychain.IdentityQueryTypeCTK,
	})
	if err != nil {
		return nil, fmt.Errorf("getting identity with label %q: %w", label, err)
	}
	signer, err := identity.Signer()
	if err != nil {
		return nil, fmt.Errorf("getting signer: %w", err)
	}
	chain, err := identity.CertificateChain(nil)
	if err != nil {
		return nil, fmt.Errorf("getting certificate chain: %w", err)
	}
	dpopSigner, err := dpop.NewSignerWithCertificateChain(signer, chain)
	if err != nil {
		return nil, fmt.Errorf("creating dpop signer: %w", err)
	}
	return dpopSigner, nil
}
