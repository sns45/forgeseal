// Package main is a minimal Go HTTP service used as a forgeseal dogfood fixture.
package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello from go-app " + uuid.NewString()))
	})
	log.Fatal(http.ListenAndServe(":8080", r))
}
