package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kitbuilder587/cheapgpt-confidential-gateway/attestation"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/internal/gateway"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/policy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gateway stopped: startup or server failure")
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	socket := flag.String("dstack-socket", "/var/run/dstack.sock", "dstack guest agent socket")
	showPolicy := flag.Bool("policy-hash", false, "print the compiled egress policy hash")
	flag.Parse()
	if *showPolicy {
		fmt.Println(policy.Hash())
		return nil
	}
	s, err := gateway.New(attestation.NewDstack(*socket), os.Getenv("GATEWAY_AUTH_TOKEN"))
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	err = s.Probe(ctx)
	cancel()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: nil}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		drain, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := server.Shutdown(drain); err != nil {
			_ = server.Close()
		}
		err := <-done
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
