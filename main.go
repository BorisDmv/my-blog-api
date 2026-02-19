package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/BorisDmv/my-blog-api/internal/config"
	"github.com/BorisDmv/my-blog-api/internal/db"
	"github.com/BorisDmv/my-blog-api/internal/handlers"
	appmiddleware "github.com/BorisDmv/my-blog-api/internal/middleware"
)

func main() {
	cfg := config.Load()

	ctx := context.Background()
	store, err := db.NewStore(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db connect failed: %v", err)
	}
	defer store.Close()

	// Create tables if not exist
	conn, err := store.Pool().Acquire(ctx)
	if err != nil {
		log.Fatalf("failed to acquire db connection: %v", err)
	}
	defer conn.Release()

	postsTableSQL := `CREATE TABLE IF NOT EXISTS posts (
	    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	    author TEXT NOT NULL,
	    title TEXT NOT NULL,
	    slug TEXT NOT NULL UNIQUE,
	    summary TEXT,
	    tags TEXT[],
	    content JSONB NOT NULL,
	    status TEXT NOT NULL DEFAULT 'draft',
	    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	);`
	_, err = conn.Exec(ctx, postsTableSQL)
	if err != nil {
		log.Fatalf("failed to create posts table: %v", err)
	}

	usersTableSQL := `CREATE TABLE IF NOT EXISTS users (
	    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	    username TEXT NOT NULL UNIQUE,
	    password_hash TEXT NOT NULL,
	    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	);`
	_, err = conn.Exec(ctx, usersTableSQL)
	if err != nil {
		log.Fatalf("failed to create users table: %v", err)
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.New(cors.Options{
		AllowedOrigins:   cfg.CorsAllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}).Handler)

	r.Get("/health", handlers.Health)

	postsHandler := handlers.NewPostsHandler(store)

	r.Route("/api", func(r chi.Router) {
		r.Use(handlers.WithStore(store))

		// In-memory rate limiter: 5 login attempts per minute per IP
		loginRateLimiter := appmiddleware.NewRateLimiter(5, time.Minute)
		r.With(loginRateLimiter.Limit).Post("/login", handlers.Login)

		//r.Post("/signup", handlers.Signup)

		// Less restrictive rate limiter: 30 requests per minute per IP for public posts and search
		publicLimiter := appmiddleware.NewRateLimiter(30, time.Minute)
		r.With(publicLimiter.Limit).Get("/posts", postsHandler.ListPublic)
		r.With(publicLimiter.Limit).Get("/posts/search", postsHandler.Search)
		r.Get("/post", postsHandler.GetByID)
		r.Get("/post/{slug}", postsHandler.GetBySlug)
		r.Get("/post/slug", postsHandler.GetBySlug)
		r.Get("/post/slug/{slug}", postsHandler.GetBySlug)

		// JWT-protected create post
		r.Group(func(r chi.Router) {
			r.Use(handlers.JWTAuth)
			r.Post("/posts", postsHandler.Create)
		})

		r.Route("/private", func(r chi.Router) {
			r.Use(appmiddleware.Auth(cfg.AuthToken))
			r.Get("/ping", handlers.PrivatePing)
		})
	})

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("listening on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
