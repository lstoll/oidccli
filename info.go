package main

import (
	"context"
	"encoding/json"
	"fmt"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/provider"
)

// InfoCmd outputs information about the auth response
type InfoCmd struct{}

// Run executes the info command
// Parameters are optional - if bound via kong.Bind(), they will be injected automatically
func (i *InfoCmd) Run(ctx context.Context, prov *provider.Provider, ts oauth2.TokenSource) error {
	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}

	fmt.Printf("Access Token: %s\n", tok.AccessToken)
	fmt.Printf("Access Token expires: %s\n", tok.Expiry.String())
	if isJWT(tok.AccessToken) {
		// TODO - add access token verification
	}
	fmt.Printf("Refresh Token: %s\n", tok.RefreshToken)
	idt, ok := oidc.GetIDToken(tok)
	if ok {
		validator, err := prov.NewIDTokenValidator(&provider.IDTokenValidatorOpts{
			IgnoreClientID: true,
		})
		if err != nil {
			return fmt.Errorf("creating id token validator: %w", err)
		}
		claims, err := prov.VerifyAndDecodeIDToken(tok, validator)
		if err != nil {
			return fmt.Errorf("ID token verification: %w", err)
		}

		clJSON, err := claims.JSONPayload()
		if err != nil {
			return fmt.Errorf("getting id token json payload: %w", err)
		}

		allClaims := make(map[string]any)
		if err := json.Unmarshal(clJSON, &allClaims); err != nil {
			return fmt.Errorf("unmarshalling id token claims: %w", err)
		}

		clJSON, err = json.MarshalIndent(allClaims, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling id token claims: %w", err)
		}

		exp, err := claims.ExpiresAt()
		if err != nil {
			return fmt.Errorf("getting id token expires at: %w", err)
		}

		fmt.Printf("ID token: %s\n", idt)
		fmt.Printf("ID token expires at: %s\n", exp)
		fmt.Printf("ID token claims: \n%s\n", string(clJSON))
	}

	return nil
}
