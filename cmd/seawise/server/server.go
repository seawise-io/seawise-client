package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/certs"
	"github.com/seawise/client/internal/config"
	"github.com/seawise/client/internal/connection"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/frp"
	"github.com/seawise/client/internal/paths"
)

type Server struct {
	mu          sync.RWMutex
	shutdownCtx context.Context
	cancel      context.CancelFunc

	apiClient   *api.Client
	cfg         *config.Config
	frpClient   *frp.Client
	connManager *connection.Manager
	certManager *certs.CertManager
	auth        *authManager

	pairingCode       string
	pairingDeviceCode string
	pairingState      string
	pairingCancel     context.CancelFunc
	e2eTLSEnabled     bool
	latestVersion     string

	serviceCache     map[string]string
	lastHealthStatus map[string]string

	restartInProgress atomic.Bool
}

func Run(port int) {
	s := &Server{
		pairingState:     "none",
		auth:             newAuthManager(),
		serviceCache:     make(map[string]string),
		lastHealthStatus: make(map[string]string),
	}
	s.run(port)
}

func (s *Server) run(port int) {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(os.Getenv("SEAWISE_LOG_LEVEL")),
	})))
	slog.Info("SeaWise Client starting", "component", "main", "version", constants.Version)

	ctx, cancel := context.WithCancel(context.Background())
	s.shutdownCtx = ctx
	s.cancel = cancel

	apiClient, err := api.New(config.GetAPIURL(nil))
	if err != nil {
		slog.Error("Invalid API URL", "component", "main", "error", err)
		os.Exit(1)
	}
	s.apiClient = apiClient

	s.connManager = connection.NewManager(connection.DefaultConfig())
	s.connManager.SetCallbacks(
		func(old, newState connection.State) {
			slog.Info("Connection state changed", "component", "main", "old_state", string(old), "new_state", string(newState))
			if newState == connection.StateConnected && (old == connection.StateReconnecting || old == connection.StateConnecting) {
				s.mu.Lock()
				s.lastHealthStatus = make(map[string]string)
				s.mu.Unlock()
				go func() {
					select {
					case <-time.After(constants.PostReconnectHealthCheckDelay):
					case <-s.shutdownCtx.Done():
						return
					}
					s.checkAndReportHealth()
				}()
			}
		},
		func() {
			slog.Info("Unpair requested by server", "component", "main")
			s.handleUnpairInternal()
		},
	)

	if err := config.MigrateLegacy(); err != nil {
		slog.Error("Config migration failed, refusing to start", "component", "main", "error", err)
		os.Exit(1)
	}

	if config.Exists() {
		var err error
		s.cfg, err = config.Load()
		if err != nil {
			slog.Warn("Failed to load config", "component", "main", "error", err)
			s.pairingState = "none"
			s.connManager.SetState(connection.StateDisconnected)
		} else {
			slog.Info("Already paired as server", "component", "main", "server_name", s.cfg.ServerName, "server_id", s.cfg.ServerID)
			storedClient, apiErr := api.New(s.cfg.APIURL)
			if apiErr != nil {
				slog.Warn("Invalid stored API URL", "component", "main", "error", apiErr)
			} else {
				s.apiClient = storedClient
			}
			s.apiClient.SetFRPToken(s.cfg.FRPToken)
			s.pairingState = "paired"
			s.connManager.SetState(connection.StateConnecting)

			go func() {
				if err := syncMachineServicesFromServer(s.shutdownCtx, s.apiClient, s.cfg.ServerID); err != nil {
					slog.Warn("Initial machine-services sync failed", "component", "main", "error", err)
				}
			}()

			s.startServices(ctx)
		}
	} else {
		s.pairingState = "none"
		s.connManager.SetState(connection.StateUnpaired)
	}

	srv := s.startWebUI(ctx, port)

	slog.Info("SeaWise Client running", "component", "main")
	slog.Info("Open web UI to manage this server", "component", "main", "url", fmt.Sprintf("http://localhost:%d", port))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	slog.Info("Shutting down...", "component", "main")

	cancel()

	httpShutdownCtx, httpShutdownRelease := context.WithTimeout(context.Background(), 5*time.Second)
	defer httpShutdownRelease()
	if err := srv.Shutdown(httpShutdownCtx); err != nil {
		slog.Error("HTTP server shutdown error", "component", "main", "error", err)
	}

	s.mu.RLock()
	shutdownCfg := s.cfg
	shutdownAPIClient := s.apiClient
	s.mu.RUnlock()
	if shutdownCfg != nil && shutdownAPIClient != nil {
		offlineCtx, offlineCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := shutdownAPIClient.MarkOffline(offlineCtx, shutdownCfg.ServerID); err != nil {
			slog.Error("Failed to notify API of shutdown", "component", "main", "error", err)
		} else {
			slog.Info("Notified API: server going offline", "component", "main")
		}
		offlineCancel()
	}

	s.connManager.Stop()
	s.auth.Stop()
	s.mu.RLock()
	client := s.frpClient
	s.mu.RUnlock()
	if client != nil {
		if err := client.Stop(); err != nil {
			slog.Error("FRP stop error", "component", "frp", "error", err)
		}
	}
	slog.Info("Shutdown complete", "component", "main")
}

func (s *Server) startServices(ctx context.Context) {
	s.mu.RLock()
	cfgSnapshot := s.cfg
	apiClient := s.apiClient
	s.mu.RUnlock()
	if cfgSnapshot == nil || apiClient == nil {
		slog.Error("startServices called before pair config loaded", "component", "main")
		return
	}

	frpServerAddr := cfgSnapshot.FRPServerAddr
	if frpServerAddr == "" {
		frpServerAddr = os.Getenv("FRP_SERVER_ADDR")
	}
	if frpServerAddr == "" {
		frpServerAddr = constants.DockerHostInternal
	}

	frpServerPort := cfgSnapshot.FRPServerPort
	if frpServerPort == 0 {
		frpServerPort = constants.DefaultFRPServerPort
	}

	frpToken := cfgSnapshot.FRPToken

	slog.Info("Connecting to FRP server", "component", "frp", "addr", frpServerAddr, "port", frpServerPort, "tls", cfgSnapshot.FRPUseTLS) // #nosec G706

	var e2eTLSEnabled bool
	var certManager *certs.CertManager

	certStatus, err := apiClient.GetCertStatus(ctx)
	if err != nil {
		slog.Error("Failed to check E2E TLS status", "component", "e2e_tls", "error", err)
	} else {
		e2eTLSEnabled = certStatus.E2ETLSEnabled
		slog.Info("E2E TLS status", "component", "e2e_tls", "enabled", e2eTLSEnabled)
	}

	if e2eTLSEnabled {
		certManager = certs.New(paths.DataDir())
		if err := certManager.EnsureDir(); err != nil {
			slog.Error("Failed to create certs dir", "component", "e2e_tls", "error", err)
			e2eTLSEnabled = false
			certManager = nil
		}
	}

	frpClient := frp.New(frp.Config{
		ServerAddr: frpServerAddr,
		ServerPort: frpServerPort,
		Token:      frpToken,
		ServerID:   cfgSnapshot.ServerID,
		UseTLS:     cfgSnapshot.FRPUseTLS,
	})

	frpClient.SetOnStateChange(func(state frp.ProcessState) {
		slog.Info("FRP process state changed", "component", "main", "state", string(state))
		if state == frp.ProcessCrashed {
			s.connManager.SetState(connection.StateReconnecting)
			go s.handleFRPCrash()
		}
	})

	s.mu.Lock()
	s.frpClient = frpClient
	s.certManager = certManager
	s.e2eTLSEnabled = e2eTLSEnabled
	s.mu.Unlock()

	slog.Info("FRP client initialized, ready to add services", "component", "frp")

	services, err := s.apiClient.ListServices(ctx, cfgSnapshot.ServerID)
	if err != nil {
		slog.Error("Failed to load services from API", "component", "main", "error", err)
	} else if len(services) > 0 {
		slog.Info("Loading services from API", "component", "main", "count", len(services))
		for _, svc := range services {
			frpSvc := frp.Service{
				Name:      svc.Name,
				LocalIP:   svc.Host,
				LocalPort: svc.Port,
				Subdomain: svc.Subdomain,
			}

			s.configureServiceTLS(&frpSvc, svc.Subdomain)
			s.frpClient.AddServiceWithoutRestart(frpSvc)
		}
	}

	if err := s.frpClient.Start(); err != nil {
		slog.Error("Failed to start FRP", "component", "frp", "error", err)
		s.connManager.SetState(connection.StateReconnecting)
	} else {
		s.connManager.SetState(connection.StateConnected)
	}

	go s.heartbeatLoop(ctx)
	go s.serviceSyncLoop(ctx)
	go s.serviceHealthLoop(ctx)
	go s.checkForUpdates(ctx)
}
