package models

import (
	"encoding/json"
	"time"
)

type Post struct {
	ID      string          `json:"id"`
	Author  string          `json:"author"`
	Title   string          `json:"title"`
	Slug    string          `json:"slug"`
	Summary string          `json:"summary"`
	Tags    []string        `json:"tags"`
	Content json.RawMessage `json:"content"`
	// Status can be "draft" or "published"
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type PostListItem struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Title     string    `json:"title"`
	Slug      string    `json:"slug"`
	Summary   string    `json:"summary"`
	Tags      []string  `json:"tags"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}
