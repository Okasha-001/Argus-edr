package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/argus-edr/argus/internal/fleet"
	"github.com/argus-edr/argus/internal/fleet/fleetpb"
	"github.com/argus-edr/argus/internal/version"
	"github.com/argus-edr/argus/server/api"
	"github.com/argus-edr/argus/server/correlate"
	"github.com/argus-edr/argus/server/ruleset"
	"github.com/argus-edr/argus/server/store"
)

const shutdownGrace = 10 * time.Second

func runServe(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	grpcAddr := flags.String("grpc", ":8443", "gRPC (mTLS) listen address")
	httpAddr := flags.String("http", "127.0.0.1:8080", "admin HTTP API listen address")
	rulesDir := flags.String("rules", "rules", "directory of YAML detection rules to distribute")
	caFile := flags.String("ca", "", "CA certificate (PEM)")
	certFile := flags.String("cert", "", "server certificate (PEM)")
	keyFile := flags.String("key", "", "server private key (PEM)")
	dev := flags.Bool("dev", false, "generate ephemeral dev certs and write agent certs to --cert-dir")
	certDir := flags.String("cert-dir", "fleet-certs", "directory --dev writes generated certs to")
	dnsName := flags.String("dns", "argus-server", "server certificate DNS name when generating dev certs")
	token := flags.String("token", os.Getenv("ARGUS_ENROLLMENT_TOKEN"), "required enrollment token (empty = open enrollment)")
	ttl := flags.Duration("heartbeat-ttl", 90*time.Second, "treat an agent offline after this long without a heartbeat")
	window := flags.Duration("correlate-window", 5*time.Minute, "cross-host correlation window")
	minHosts := flags.Int("correlate-min-hosts", 3, "distinct hosts before a cross-host signal fires")
	if err := flags.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	tlsConfig, err := buildServerTLS(serverTLSOptions{
		dev: *dev, certDir: *certDir, dnsName: *dnsName,
		caFile: *caFile, certFile: *certFile, keyFile: *keyFile, logger: logger,
	})
	if err != nil {
		return err
	}

	rules, err := ruleset.NewProvider(*rulesDir)
	if err != nil {
		return err
	}

	memStore := store.NewMemory()
	correlator := correlate.NewCrossHost(*window, *minHosts)
	admin := newAdminAPI(memStore, rules, *ttl)
	reloadOnHangup(rules, logger)
	if *token == "" {
		logger.Warn("open enrollment: no --token set, any agent with a valid client certificate can enroll")
	}

	service := api.New(api.Deps{
		Store:      memStore,
		Rules:      rules,
		Correlator: correlator,
		Token:      *token,
		OnSignal:   admin.recordSignal,
		Logger:     logger,
	})

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	fleetpb.RegisterFleetServiceServer(grpcServer, service)
	httpServer := &http.Server{Addr: *httpAddr, Handler: admin.mux(), ReadHeaderTimeout: 5 * time.Second}

	return serveUntilSignal(serveTargets{
		grpc: grpcServer, grpcAddr: *grpcAddr,
		http: httpServer, logger: logger,
		rulesVersion: rules.Version(),
	})
}

type serveTargets struct {
	grpc         *grpc.Server
	grpcAddr     string
	http         *http.Server
	logger       *slog.Logger
	rulesVersion string
}

// serveUntilSignal starts the gRPC and admin HTTP servers, then blocks until a
// termination signal or a fatal listen error, draining both gracefully.
func serveUntilSignal(t serveTargets) error {
	listener, err := net.Listen("tcp", t.grpcAddr)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 2)
	go func() { errc <- t.grpc.Serve(listener) }()
	go func() { errc <- t.http.ListenAndServe() }()

	t.logger.Info("argus-server listening",
		"grpc", t.grpcAddr, "http", t.http.Addr,
		"version", version.Version, "rules_version", t.rulesVersion)

	select {
	case <-ctx.Done():
		t.logger.Info("signal received, shutting down")
	case err := <-errc:
		stop()
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, grpc.ErrServerStopped) {
			t.grpc.Stop()
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	t.grpc.GracefulStop()
	if err := t.http.Shutdown(shutdownCtx); err != nil {
		t.logger.Warn("admin http shutdown", "err", err)
	}
	return nil
}

// reloadOnHangup re-reads the ruleset on SIGHUP, the conventional way to tell a
// daemon to pick up edited config without a restart. Agents then converge on the
// next heartbeat. The goroutine lives for the process's lifetime.
func reloadOnHangup(rules *ruleset.Provider, logger *slog.Logger) {
	hangup := make(chan os.Signal, 1)
	signal.Notify(hangup, syscall.SIGHUP)
	go func() {
		for range hangup {
			if err := rules.Reload(); err != nil {
				logger.Error("rule reload (SIGHUP) failed, keeping current ruleset", "err", err)
				continue
			}
			logger.Info("ruleset reloaded (SIGHUP)", "version", rules.Version())
		}
	}()
}

type serverTLSOptions struct {
	dev                       bool
	certDir, dnsName          string
	caFile, certFile, keyFile string
	logger                    *slog.Logger
}

// buildServerTLS loads the mTLS config from files, or, in dev mode, mints a
// throwaway CA and writes matching agent certs so a local agent can connect.
func buildServerTLS(opts serverTLSOptions) (*tls.Config, error) {
	if opts.dev {
		certs, err := fleet.GenerateDevCerts(opts.dnsName)
		if err != nil {
			return nil, err
		}
		if err := fleet.WriteDevCerts(opts.certDir, certs); err != nil {
			return nil, err
		}
		opts.logger.Warn("dev mode: using generated certificates, not for production",
			"cert_dir", opts.certDir, "dns", opts.dnsName)
		return fleet.ServerTLSConfig(certs.CA.Cert, certs.Server.Cert, certs.Server.Key)
	}
	if opts.caFile == "" || opts.certFile == "" || opts.keyFile == "" {
		return nil, errors.New("--ca, --cert and --key are required (or use --dev)")
	}
	return fleet.ServerTLSConfigFromFiles(opts.caFile, opts.certFile, opts.keyFile)
}
