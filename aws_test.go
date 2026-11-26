package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestCredentialProcessFromCreds(t *testing.T) {
	exp := time.Date(2026, 11, 26, 16, 0, 0, 0, time.FixedZone("CET", 3600))
	got, err := json.Marshal(credentialProcessFromCreds(&types.Credentials{
		AccessKeyId:     aws.String("ASIAEXAMPLE"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
		Expiration:      &exp,
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Version":1,"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secret","SessionToken":"token","Expiration":"2026-11-26T15:00:00Z"}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}

	got, err = json.Marshal(credentialProcessFromCreds(&types.Credentials{
		AccessKeyId:     aws.String("ASIAEXAMPLE"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	want = `{"Version":1,"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secret","SessionToken":"token"}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
