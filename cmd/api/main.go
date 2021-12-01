package main

import (
	"context"
	"fmt"
	"github.com/interfere/go-papyrus/v2/internal/server"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/interfere/go-papyrus/v2/internal/config"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func main() {
	// load configs
	apiConfig := config.New()
	if err := apiConfig.LoadConfigFromEnv(); err != nil {
		panic(errors.Wrap(err, "unable to load env config"))
	}

	// set up lg
	lg, err := zap.NewDevelopment()
	if err != nil {
		panic(errors.Wrap(err, "unable to create lg"))
	}
	// nolint:errcheck
	defer lg.Sync()

	seed := time.Now().UnixNano()

	lg = lg.With(
		zap.String("env", apiConfig.AppEnv),
		zap.String("program", apiConfig.AppName),
		zap.String("channel", apiConfig.LogChannel),
		zap.String("version", apiConfig.Version),
		zap.Int64("seed", seed),
	)

	// create app context
	apiCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	authServer := server.NewServer(lg)

	// http server
	httpServer := http.Server{
		Addr:         fmt.Sprintf(":%d", apiConfig.Port),
		Handler:      authServer.RoutesHandler(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// start web server
	go func() {
		lg.Info("starting web server", zap.Int("port", apiConfig.Port), zap.String("log_level", apiConfig.LogLevel))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lg.Error("http server stopped listening and serving", zap.Error(err))
		}
	}()

	// listen for stop signal
	stopSignal := make(chan os.Signal, 1)
	signal.Notify(stopSignal, syscall.SIGINT, syscall.SIGTERM)

	s := <-stopSignal
	lg.Info("received signal, gracefully shutting down", zap.String("signal", s.String()))

	// shut down HTTP Server
	if err := httpServer.Shutdown(apiCtx); err != nil {
		lg.Fatal("error occurred while shutting down server", zap.Error(err))
	}
	// cancel main context for whatever is left using it
	cancel()
	// exit
	lg.Info("shutdown done. Have a nice day!")
	// nolint: gocritic
	os.Exit(0)
}
