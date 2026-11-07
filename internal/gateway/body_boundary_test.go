package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// Policy limits are inclusive. The connector must inspect the final allowed
// byte while rejecting the next byte for known and streaming request lengths.
func TestInclusiveRequestBodyBoundary(t *testing.T) {
	for _, mode := range []string{"enforcing", "detection", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			var received atomic.Int64
			g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				received.Store(int64(len(body)))
				_, _ = w.Write([]byte("backend-ok"))
			})
			c := g.Config()
			c.RequestLimit, c.Mode = 1024, mode
			if _, err := g.Apply(c, false); err != nil {
				t.Fatal(err)
			}
			for _, contentType := range []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data; boundary=OpenWAFBoundary"} {
				for _, streaming := range []bool{false, true} {
					for _, size := range []int{1023, 1024, 1025} {
						prefix, suffix := `{"message":"`, `"}`
						if strings.HasPrefix(contentType, "application/x-www") {
							prefix, suffix = "message=", ""
						}
						if strings.HasPrefix(contentType, "multipart/") {
							prefix = "--OpenWAFBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"safe.csv\"\r\nContent-Type: text/csv\r\n\r\n"
							suffix = "\r\n--OpenWAFBoundary--\r\n"
						}
						body := prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix
						r := httptest.NewRequest("POST", "http://example.test/", strings.NewReader(body))
						r.Header.Set("Content-Type", contentType)
						r.Header.Set("User-Agent", "OpenWAF boundary test")
						if streaming {
							r.ContentLength = -1
							r.TransferEncoding = []string{"chunked"}
						} else {
							r.Header.Set("Content-Length", strconv.Itoa(size))
						}
						received.Store(-1)
						w := httptest.NewRecorder()
						g.ServeHTTP(w, r)
						if size <= 1024 {
							if w.Code != 200 || received.Load() != int64(size) {
								t.Fatalf("%s streaming=%v size=%d: status=%d received=%d", contentType, streaming, size, w.Code, received.Load())
							}
						} else if w.Code != 413 || received.Load() != -1 {
							t.Fatalf("oversize forwarded: status=%d received=%d", w.Code, received.Load())
						}
					}
				}
			}
			// The fix must not create an uninspected last-byte window.
			prefix, suffix := `{"q":"`, `<script>alert(1)</script>"}`
			body := prefix + strings.Repeat("a", 1024-len(prefix)-len(suffix)) + suffix
			expected := 200
			if mode == "enforcing" {
				expected = 403
			}
			if w := request(g, "POST", "/", "application/json", body); w.Code != expected {
				t.Fatalf("boundary XSS status=%d, expected=%d", w.Code, expected)
			}
		})
	}
}

func TestInclusiveInspectedResponseBoundary(t *testing.T) {
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		size, _ := strconv.Atoi(r.URL.Query().Get("size"))
		w.Header().Set("Content-Type", "text/plain")
		body := strings.Repeat("a", size)
		if r.URL.Query().Get("secret") == "1" {
			body = strings.Repeat("a", size-len("boundary-private-marker")) + "boundary-private-marker"
		}
		_, _ = io.WriteString(w, body)
	})
	c := g.Config()
	c.InspectResponse, c.ResponseLimit = true, 1024
	c.CustomRules = `SecRule RESPONSE_BODY "@endsWith boundary-private-marker" "id:100161,phase:4,deny,status:403,log,msg:'Boundary response inspected'"`
	if _, err := g.Apply(c, false); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1023, 1024, 1025} {
		w := request(g, "GET", "/?size="+strconv.Itoa(size), "", "")
		if size <= 1024 {
			if w.Code != 200 || w.Body.Len() != size {
				t.Fatalf("response size=%d: status=%d bytes=%d", size, w.Code, w.Body.Len())
			}
		} else if w.Code != 502 {
			t.Fatalf("oversize response status=%d", w.Code)
		}
	}
	if w := request(g, "GET", "/?size=1024&secret=1", "", ""); w.Code != 403 || strings.Contains(w.Body.String(), "boundary-private-marker") {
		t.Fatal("final allowed response bytes escaped inspection", w.Code)
	}
}
