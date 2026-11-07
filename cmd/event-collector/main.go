package main

import (
	"context"
	"flag"
	"golang.org/x/net/netutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/credentials"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventcollector"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9095", "Collector listener; remote binding requires TLS")
	path := flag.String("db", "data/collector.db", "Durable collector database")
	tokenFile := flag.String("token-file", "", "Restricted collector credential file, alternatively OPENWAF_COLLECTOR_TOKEN")
	startupTimeout := flag.Duration("storage-startup-timeout", 30*time.Second, "Storage initialization budget, 1s..2m")
	budget := flag.Int64("db-mib", 256, "Maximum main database size in MiB (4..1024); no automatic event deletion")
	cert := flag.String("tls-cert", "", "TLS certificate PEM")
	key := flag.String("tls-key", "", "TLS private-key PEM")
	flag.Parse()
	if *budget < 4 || *budget > 1024 || (*cert == "") != (*key == "") {
		log.Fatal("invalid collector disk/TLS settings")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || (net.ParseIP(host) == nil) || (*cert == "" && !net.ParseIP(host).IsLoopback()) {
		log.Fatal("bind to an explicit loopback IP, or configure TLS for a remote listener")
	}
	token, err := credentials.Value("OPENWAF_COLLECTOR_TOKEN", *tokenFile)
	if err != nil {
		log.Fatal(err)
	}
	collector, err := eventcollector.Open(eventcollector.Options{Path: *path, Token: token, MaxBytes: *budget << 20, StartupTimeout: *startupTimeout})
	if err != nil {
		log.Fatal(err)
	}
	defer collector.Close()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	listener = netutil.LimitListener(listener, 256)
	server := &http.Server{Handler: collector, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	stopped := make(chan error, 1)
	go func() {
		if *cert != "" {
			stopped <- server.ServeTLS(listener, *cert, *key)
		} else {
			stopped <- server.Serve(listener)
		}
	}()
	log.Printf("Reference event collector listening on %s; database %s", listener.Addr(), *path)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	select {
	case <-signals:
	case err = <-stopped:
		if err != http.ErrServerClosed {
			log.Printf("Collector listener failed: %v", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = server.Shutdown(ctx); err != nil {
		server.Close()
	}
}
