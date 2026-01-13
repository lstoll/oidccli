package main

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oidc"
)

// RawCmd outputs a raw JWT token
type RawCmd struct {
	UseAccessToken bool `help:"Use access token, rather than id_token"`
}

// Run executes the raw command
// Parameters are optional - if bound via kong.Bind(), they will be injected automatically
func (r *RawCmd) Run(ctx context.Context, ts oauth2.TokenSource) error {
	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}
	raw := tok.AccessToken
	if !r.UseAccessToken {
		idt, ok := oidc.GetIDToken(tok)
		if !ok {
			return fmt.Errorf("response has no id_token")
		}
		raw = idt
	}
	fmt.Print(raw)
	return nil
}
