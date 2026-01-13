package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oidc"
)

const (
	apiVersion   = "client.authentication.k8s.io/v1beta1"
	execCredKind = "ExecCredential"
)

// kubeExecCred represents the Kubernetes exec credential response
type kubeExecCred struct {
	APIVersion string    `json:"apiVersion,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Status     kubeToken `json:"status"`
}

// KubernetesCmd outputs credentials in Kubernetes exec credential format
type KubernetesCmd struct {
	UseAccessToken bool `help:"Use access token, rather than id_token"`
}

// Run executes the kubernetes command
func (k *KubernetesCmd) Run(ctx context.Context, ts oauth2.TokenSource) error {
	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}
	var raw = tok.AccessToken
	if !k.UseAccessToken {
		idt, ok := oidc.GetIDToken(tok)
		if !ok {
			return fmt.Errorf("response has no id_token")
		}
		raw = idt
	}
	creds := kubeExecCred{
		APIVersion: apiVersion,
		Kind:       execCredKind,
		Status: kubeToken{
			Token:               raw,
			ExpirationTimestamp: &tok.Expiry,
		},
	}
	return json.NewEncoder(os.Stdout).Encode(&creds)
}
