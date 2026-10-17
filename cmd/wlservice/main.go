package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"whitelist-mikrotik/internal/config"
	"whitelist-mikrotik/internal/httpserver"
	"whitelist-mikrotik/internal/ipcheck"
	"whitelist-mikrotik/internal/mikrotik"
)

func main() {
	// 1. Initialize slog JSON logger (default stdout)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// 2. Load and validate configuration from environment
	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	logger.Info("configuration loaded successfully", "config", cfg.String())

	// 3. Initialize components
	validator := ipcheck.NewValidator(cfg.AllowIPv6, cfg.OfficePublicIPs)
	mkClient := mikrotik.NewClient(cfg, logger)
	defer func() {
		if err := mkClient.Close(); err != nil {
			logger.Warn("error closing mikrotik client", "error", err)
		}
	}()

	handler := httpserver.NewHandler(validator, mkClient, logger)
	router := httpserver.SetupRouter(handler, cfg.AuthBearerToken, logger)

	// 4. Configure http.Server with production timeouts
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// 5. Graceful shutdown setup
	serverErrChan := make(chan error, 1)
	go func() {
		logger.Info("starting whitelist service", "listen_addr", cfg.ListenAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- err
		}
	}()

	stopSignal := make(chan os.Signal, 1)
	signal.Notify(stopSignal, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrChan:
		logger.Error("server encountered fatal error", "error", err)
		os.Exit(1)
	case sig := <-stopSignal:
		logger.Info("received termination signal, initiating graceful shutdown", "signal", sig.String())
	}

	// Graceful shutdown with 10s timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("service shutdown complete")
}
