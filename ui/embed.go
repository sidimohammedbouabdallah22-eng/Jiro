package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed dashboard.html app.js styles.css
var assets embed.FS

func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			b, _ := fs.ReadFile(assets, "dashboard.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(b)
			return
		}
		if r.URL.Path != "/app.js" && r.URL.Path != "/styles.css" {
			http.NotFound(w, r)
			return
		}
		http.FileServer(http.FS(assets)).ServeHTTP(w, r)
	})
}
