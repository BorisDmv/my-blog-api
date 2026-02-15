package handlers

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/BorisDmv/my-blog-api/internal/db"
	"github.com/BorisDmv/my-blog-api/internal/models"
)

// JWT secret for demo (in real apps, use env/config).
func getJWTSecret() []byte {
	return []byte(os.Getenv("JWT_SECRET"))
}

type contextKey string

const storeContextKey contextKey = "store"

func WithStore(store *db.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), storeContextKey, store)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func getStore(r *http.Request) (*db.Store, bool) {
	store, ok := r.Context().Value(storeContextKey).(*db.Store)
	return store, ok && store != nil
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type SignupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SignupResponse struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

// Login authenticates a user from the DB and returns a JWT.
func Login(w http.ResponseWriter, r *http.Request) {
	jwtSecret := getJWTSecret()
	if len(jwtSecret) == 0 {
		respondError(w, http.StatusInternalServerError, "JWT secret not set")
		return
	}
	store, ok := getStore(r)
	if !ok {
		respondError(w, http.StatusInternalServerError, "store not available")
		return
	}
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Username == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "username and password required")
		return
	}
	user, err := store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		log.Printf("login db error: %v", err)
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}
	if user == nil || !checkPasswordHash(req.Password, user.PasswordHash) {
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":      user.ID,
		"username": user.Username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "token error")
		return
	}
	respondJSON(w, http.StatusOK, LoginResponse{Token: tokenString})
}

// Signup creates a new user in the DB.
func Signup(w http.ResponseWriter, r *http.Request) {
	store, ok := getStore(r)
	if !ok {
		respondError(w, http.StatusInternalServerError, "store not available")
		return
	}
	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Username == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "username and password required")
		return
	}
	existing, err := store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		log.Printf("signup db error: %v", err)
		respondError(w, http.StatusInternalServerError, "db error")
		return
	}
	if existing != nil {
		respondError(w, http.StatusConflict, "username already exists")
		return
	}
	hash := hashPassword(req.Password)
	created, err := store.CreateUser(r.Context(), models.User{
		Username:     req.Username,
		PasswordHash: hash,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create user")
		return
	}
	respondJSON(w, http.StatusOK, SignupResponse{
		Username:     created.Username,
		PasswordHash: created.PasswordHash,
	})
}

func hashPassword(password string) string {
	h := sha512.New()
	_, _ = h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

func checkPasswordHash(password, hash string) bool {
	return hashPassword(password) == hash
}

// Auth middleware for JWT.
func JWTAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtSecret := getJWTSecret()
		if len(jwtSecret) == 0 {
			http.Error(w, "server auth misconfigured", http.StatusInternalServerError)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tokenStr := authHeader[7:]
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type PostsHandler struct {
	store *db.Store
}

type PostsResponse struct {
	Data  interface{} `json:"data"`
	Page  int         `json:"page"`
	Limit int         `json:"limit"`
	Total int         `json:"total"`
}

type CreatePostRequest struct {
	Author  string          `json:"author"`
	Title   string          `json:"title"`
	Slug    string          `json:"slug"`
	Summary string          `json:"summary"`
	Tags    []string        `json:"tags"`
	Content json.RawMessage `json:"content"`
	Status  string          `json:"status"`
}

func NewPostsHandler(store *db.Store) *PostsHandler {
	return &PostsHandler{store: store}
}

func (h *PostsHandler) ListPublic(w http.ResponseWriter, r *http.Request) {
	page := parsePositiveInt(r.URL.Query().Get("page"), 1)
	limit := parsePositiveInt(r.URL.Query().Get("limit"), 10)
	if limit > 100 {
		limit = 100
	}

	offset := (page - 1) * limit

	posts, total, err := h.store.ListPosts(r.Context(), limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load posts")
		return
	}

	respondJSON(w, http.StatusOK, PostsResponse{
		Data:  posts,
		Page:  page,
		Limit: limit,
		Total: total,
	})
}

func (h *PostsHandler) Search(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		query = r.URL.Query().Get("query")
	}
	if query == "" {
		respondError(w, http.StatusBadRequest, "missing search query")
		return
	}

	page := parsePositiveInt(r.URL.Query().Get("page"), 1)
	limit := parsePositiveInt(r.URL.Query().Get("limit"), 10)
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	posts, total, err := h.store.SearchPosts(r.Context(), query, limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to search posts")
		return
	}

	respondJSON(w, http.StatusOK, PostsResponse{
		Data:  posts,
		Page:  page,
		Limit: limit,
		Total: total,
	})
}

func (h *PostsHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing id")
		return
	}
	post, err := h.store.GetPostByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load post")
		return
	}
	if post == nil {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	respondJSON(w, http.StatusOK, post)
}

func (h *PostsHandler) GetBySlug(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		slug = r.URL.Query().Get("slug")
	}
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing slug")
		return
	}
	post, err := h.store.GetPostBySlug(r.Context(), slug)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load post")
		return
	}
	if post == nil {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	respondJSON(w, http.StatusOK, post)
}

// Handler for creating a post (JWT protected).
func (h *PostsHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreatePostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Author == "" || req.Title == "" || req.Slug == "" {
		respondError(w, http.StatusBadRequest, "author, title, and slug are required")
		return
	}
	if len(req.Content) == 0 {
		respondError(w, http.StatusBadRequest, "content is required")
		return
	}

	created, err := h.store.CreatePost(r.Context(), models.Post{
		Author:  req.Author,
		Title:   req.Title,
		Slug:    req.Slug,
		Summary: req.Summary,
		Tags:    req.Tags,
		Content: req.Content,
		Status:  req.Status,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create post")
		return
	}
	respondJSON(w, http.StatusCreated, created)
}

func parsePositiveInt(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}
