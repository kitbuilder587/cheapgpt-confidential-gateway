package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kitbuilder587/cheapgpt-confidential-gateway/attestation"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/policy"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/protocol"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/sdk"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: cgw policy-hash | verify | request | tokenize")
	}
	command := os.Args[1]
	if command == "policy-hash" {
		fmt.Println(policy.Hash())
		return nil
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	base := flags.String("gateway", "", "HTTPS gateway URL")
	policyFile := flags.String("policy", "", "independently approved attestation policy JSON")
	evidenceFile := flags.String("evidence", "", "evidence JSON to verify")
	challengeHex := flags.String("challenge", "", "original 32-byte challenge in hex")
	host := flags.String("host", "", "destination hostname")
	path := flags.String("path", "", "destination request path")
	headersFile := flags.String("headers", "", "optional JSON object with upstream headers")
	encoding := flags.String("encoding", "o200k_base", "local text tokenizer encoding")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	var approved attestation.Policy
	if err := readJSON(*policyFile, &approved); err != nil {
		return errors.New("cannot read attestation policy")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	if command == "verify" {
		var e protocol.Evidence
		if err := readJSON(*evidenceFile, &e); err != nil {
			return errors.New("cannot read evidence")
		}
		challenge, err := hex.DecodeString(*challengeHex)
		if err != nil {
			return errors.New("invalid challenge")
		}
		if err := attestation.Verify(ctx, e, challenge, approved); err != nil {
			return err
		}
		fmt.Println("Verified: hardware, boot, application, egress policy, challenge and session key.")
		return nil
	}
	if command != "request" && command != "tokenize" {
		return errors.New("unknown command")
	}
	client, err := sdk.New(*base, approved)
	if err != nil {
		return err
	}
	defer client.Close()
	body, err := io.ReadAll(io.LimitReader(os.Stdin, protocol.MaxBody+1))
	if err != nil || len(body) > protocol.MaxBody {
		return errors.New("input exceeds limit")
	}
	defer clear(body)
	payload := protocol.Payload{Host: *host, Body: body}
	if command == "tokenize" {
		payload = protocol.Payload{Tokenize: &protocol.Tokenize{Encoding: *encoding, Text: string(body)}}
	} else if !json.Valid(body) {
		return errors.New("stdin must contain upstream-native JSON")
	}
	session, err := client.Session(ctx)
	if err != nil {
		return err
	}
	prepared, err := session.Prepare(payload)
	if err != nil {
		return err
	}
	if command == "request" {
		headers := map[string]string{}
		if *headersFile != "" {
			if err := readJSON(*headersFile, &headers); err != nil {
				return errors.New("cannot read upstream headers")
			}
		}
		if token := os.Getenv("UPSTREAM_TOKEN"); token != "" {
			headers["Authorization"] = "Bearer " + token
		}
		prepared.Request.Route, err = session.SealRoute(prepared.Request.Payload, protocol.Route{Host: *host, Path: *path, Headers: headers})
		if err != nil {
			return err
		}
	}
	wire, err := client.Relay(ctx, prepared.Request, os.Getenv("GATEWAY_AUTH_TOKEN"))
	if err != nil {
		return err
	}
	response, err := prepared.OpenResponse(wire)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if _, err := io.Copy(os.Stdout, response.Body); err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		return fmt.Errorf("upstream status %d", response.StatusCode)
	}
	return nil
}

func readJSON(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 2<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
