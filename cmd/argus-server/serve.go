package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	"github.com/argus-edr/argus/ui"
)

const shutdownGrace = 10 * time.Second

func runServe(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	grpcAddr := flags.String("grpc", ":8443", "gRPC (mTLS) listen address")
	httpAddr := flags.String("http", "127.0.0.1:8080", "admin HTTP API listen address")
	uiAddr := flags.String("ui-addr", "", "serve the web console on this address (empty = console off)")
	rulesDir := flags.String("rules", "rules", "directory of YAML detection rules to distribute")
	caFile := flags.String("ca", "", "CA certificate (PEM)")
	certFile := flags.String("cert", "", "server certificate (PEM)")
	keyFile := flags.String("key", "", "server private key (PEM)")
	dev := flags.Bool("dev", false, "generate ephemeral dev certs and write agent certs to --cert-dir")
	certDir := flags.String("cert-dir", "fleet-certs", "directory --dev writes generated certs to")
	dnsName := flags.String("dns", "argus-server", "server certificate DNS name when generating dev certs")
	token := flags.String("token", os.Getenv("ARGUS_ENROLLMENT_TOKEN"), "required enrollment token (empty = open enrollment)")
	adminToken := flags.String("admin-token", os.Getenv("ARGUS_ADMIN_TOKEN"), "bearer token for admin command/reload endpoints (empty = those endpoints are refused)")
	storeKind := flags.String("store", store.BackendMemory, "state backend: memory (ephemeral) or sqlite (durable)")
	dsn := flags.String("dsn", "", "data source for --store sqlite (database file path)")
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

	backing, err := store.Open(*storeKind, *dsn)
	if err != nil {
		return err
	}
	defer backing.Close()
	logger.Info("state backend", "store", *storeKind)

	correlator := correlate.NewCrossHost(*window, *minHosts)
	admin := newAdminAPI(backing, rules, *ttl, *adminToken, logger)
	reloadOnHangup(rules, logger)
	if *token == "" {
		logger.Warn("open enrollment: no --token set, any agent with a valid client certificate can enroll")
	}
	if *adminToken == "" {
		logger.Warn("admin command endpoints disabled: no --admin-token set (kill/quarantine/reload will be refused)")
	}

	service := api.New(api.Deps{
		Store:      backing,
		Rules:      rules,
		Correlator: correlator,
		Token:      *token,
		OnSignal:   admin.recordSignal,
		OnAlert:    admin.recordAlert,
		Logger:     logger,
	})

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	fleetpb.RegisterFleetServiceServer(grpcServer, service)
	adminHandler := admin.mux()
	httpServer := &http.Server{Addr: *httpAddr, Handler: adminHandler, ReadHeaderTimeout: 5 * time.Second}

	var uiServer *http.Server
	if *uiAddr != "" {
		uiServer = &http.Server{
			Addr:              *uiAddr,
			Handler:           consoleHandler(adminHandler, ui.Assets()),
			ReadHeaderTimeout: 5 * time.Second,
		}
		logger.Info("web console enabled", "ui_addr", *uiAddr)
	}

	return serveUntilSignal(serveTargets{
		grpc: grpcServer, grpcAddr: *grpcAddr,
		http: httpServer, ui: uiServer, logger: logger,
		rulesVersion: rules.Version(),
	})
}

// consoleHandler serves the embedded web console at / and routes API, health and
// version requests to the admin handler, so the browser talks to one origin (no
// CORS) while the console assets and the JSON API share a listener.
func consoleHandler(adminHandler http.Handler, assets fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isAPIPath(r.URL.Path) {
			adminHandler.ServeHTTP(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

func isAPIPath(path string) bool {
	return strings.HasPrefix(path, "/api/") || path == "/healthz" || path == "/version"
}

type serveTargets struct {
	grpc         *grpc.Server
	grpcAddr     string
	http         *http.Server
	ui           *http.Server
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

	errc := make(chan error, 3)
	go func() { errc <- t.grpc.Serve(listener) }()
	go func() { errc <- t.http.ListenAndServe() }()
	if t.ui != nil {
		go func() { errc <- t.ui.ListenAndServe() }()
	}

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
	if t.ui != nil {
		if err := t.ui.Shutdown(shutdownCtx); err != nil {
			t.logger.Warn("console http shutdown", "err", err)
		}
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
