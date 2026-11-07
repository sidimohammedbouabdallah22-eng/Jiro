package gateway

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/jcchavezs/mergefs"
)

type ruleTimingWriter struct{ file *os.File }

func (w ruleTimingWriter) Write(p []byte) (int, error) {
	_, err := fmt.Fprintf(w.file, "%d %s", time.Now().UnixNano(), p)
	return len(p), err
}

// This benchmark uses the production compiler and full configured CRS. It
// measures inspection independently of HTTP, upstreams and durable storage.
func BenchmarkJSONInspection(b *testing.B) {
	for _, size := range []int{64 << 10, 256 << 10, 900 << 10} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			c := Defaults()
			c.RequestLimit = 1 << 20
			waf, err := compile(c)
			if path := os.Getenv("OPENWAF_PROFILE_RULES"); path != "" {
				file, e := os.Create(path)
				if e != nil {
					b.Fatal(e)
				}
				defer file.Close()
				directives, e := Directives(c)
				if e != nil {
					b.Fatal(e)
				}
				waf, err = coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS)).WithDirectives(directives).WithDebugLogger(debuglog.Default().WithLevel(debuglog.LevelDebug).WithOutput(ruleTimingWriter{file})))
			}
			if err != nil {
				b.Fatal(err)
			}
			body := []byte(`{"payload":"` + strings.Repeat("a", size-14) + `"}`)
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tx := waf.NewTransaction()
				tx.ProcessConnection("127.0.0.1", 12345, "127.0.0.1", 8080)
				tx.ProcessURI("/echo", "POST", "HTTP/1.1")
				tx.SetServerName("profile.test")
				tx.AddRequestHeader("Host", "profile.test")
				tx.AddRequestHeader("Content-Type", "application/json")
				tx.AddRequestHeader("Content-Length", strconv.Itoa(len(body)))
				tx.AddRequestHeader("User-Agent", "OpenWAF profiling")
				if interruption := tx.ProcessRequestHeaders(); interruption != nil {
					b.Fatal("header interruption")
				}
				if interruption, _, err := tx.WriteRequestBody(body); err != nil || interruption != nil {
					b.Fatal("body write failed", err)
				}
				if interruption, err := tx.ProcessRequestBody(); err != nil || interruption != nil {
					b.Fatal("body inspection failed", err)
				}
				if err := tx.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
