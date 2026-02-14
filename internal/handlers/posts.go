package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/BorisDmv/my-blog-api/internal/db"
)

type PostsHandler struct {
	store *db.Store
}

type PostsResponse struct {
	Data  interface{} `json:"data"`
	Page  int         `json:"page"`
	Limit int         `json:"limit"`
	Total int         `json:"total"`
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
