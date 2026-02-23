package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/nicjohnson145/connecthelp/codec"
	pbv1beta1connect "github.com/nicjohnson145/pauth/gen/go/pauth/v1beta1/pauthv1beta1connect"
	"github.com/nicjohnson145/pauth/internal/service"
	"github.com/nicjohnson145/pauth/internal/storage"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pstore, pstoreCleanup, err := storage.NewMemoryStore(storage.MemoryStoreOpts{})
	defer pstoreCleanup()
	if err != nil {
		return err
	}

	psrv := service.NewService(service.ServiceConfig{
		PurgeEnabled:         true,
		Store:                pstore,
		InitialAdminEmail:    "admin@example.com",
		InitialAdminPassword: "admin-password",
		InitialAdminRoles: []string{
			"admin",
		},
	})

	// Call our bootstrap function on startup, in case its the first one
	if _, err := psrv.Bootstrap(ctx); err != nil {
		return err
	}
	pauthInterceptor, err := service.NewConnectInterceptor(service.ConnectInterceptorConfig{
		Store: pstore,
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()

	interceptors := []connect.Interceptor{
		pauthInterceptor,
	}

	// Auth routing
	mux.Handle(pbv1beta1connect.NewPAuthServiceHandler(
		psrv,
		connect.WithInterceptors(interceptors...),
		connect.WithCodec(codec.NewProtoJSONCodec(codec.ProtoJSONCodecOpts{
			ProtoJsonOpts: protojson.MarshalOptions{
				UseProtoNames: true,
			},
		})),
	))

	port := "8080"
	lis, err := net.Listen("tcp4", ":"+port)
	if err != nil {
		return err
	}

	httpServer := http.Server{
		Addr:              ":" + port,
		Handler:           h2c.NewHandler(mux, &http2.Server{}),
		ReadHeaderTimeout: 3 * time.Second,
	}

	// Setup signal handlers so we can gracefully shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		dieCtx, dieCancel := context.WithTimeout(ctx, 10*time.Second)
		defer dieCancel()
		_ = httpServer.Shutdown(dieCtx)
	}()

	fmt.Println("starting server")
	if err := httpServer.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}
