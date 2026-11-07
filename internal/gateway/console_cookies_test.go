package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConsoleCookiesCannotCrossApplicationListener(t *testing.T) {
	g := protocolGateway(t, Options{}, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Cookie"); strings.Contains(got, "openwaf_") || !strings.Contains(got, "business=value") {
			t.Error("console cookie reached backend", got)
		}
		w.Header().Add("Set-Cookie", "openwaf_session=attacker; Path=/")
		w.Header().Add("Set-Cookie", "business=updated; Path=/")
		w.WriteHeader(200)
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "openwaf_session=controlsecret; business=value; openwaf_oidc=transaction; openwaf_passkey=ceremony")
	r.Header.Set("User-Agent", "OpenWAF cookie isolation test")
	g.ServeHTTP(w, r)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Name != "business" {
		t.Fatal("backend replaced console cookie", w.Code, w.Header())
	}
}
