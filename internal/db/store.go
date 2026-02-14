package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/BorisDmv/my-blog-api/internal/models"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func (s *Store) ListPosts(ctx context.Context, limit, offset int) ([]models.PostListItem, int, error) {
	if s.pool == nil {
		return nil, 0, errors.New("db not initialized")
	}

	const listQuery = `
		SELECT
			id::text,
			author,
			title,
			slug,
			COALESCE(summary, ''),
			COALESCE(tags, '{}'::text[]),
			created_at
		FROM posts
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := s.pool.Query(ctx, listQuery, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list posts: %w", err)
	}
	defer rows.Close()

	posts := make([]models.PostListItem, 0, limit)
	for rows.Next() {
		var post models.PostListItem
		if err := rows.Scan(
			&post.ID,
			&post.Author,
			&post.Title,
			&post.Slug,
			&post.Summary,
			&post.Tags,
			&post.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan post: %w", err)
		}
		posts = append(posts, post)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows error: %w", err)
	}

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM posts").Scan(&total); err != nil {
		if err == pgx.ErrNoRows {
			total = 0
		} else {
			return nil, 0, fmt.Errorf("count posts: %w", err)
		}
	}

	return posts, total, nil
}

func (s *Store) GetPostByID(ctx context.Context, id string) (*models.Post, error) {
	if s.pool == nil {
		return nil, errors.New("db not initialized")
	}
	const query = `
		SELECT
			id::text,
			author,
			title,
			slug,
			COALESCE(summary, ''),
			COALESCE(tags, '{}'::text[]),
			content,
			created_at
		FROM posts
		WHERE id = $1
	`
	var post models.Post
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&post.ID,
		&post.Author,
		&post.Title,
		&post.Slug,
		&post.Summary,
		&post.Tags,
		&post.Content,
		&post.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get post: %w", err)
	}
	return &post, nil
}

func (s *Store) GetPostBySlug(ctx context.Context, slug string) (*models.Post, error) {
	if s.pool == nil {
		return nil, errors.New("db not initialized")
	}
	const query = `
		SELECT
			id::text,
			author,
			title,
			slug,
			COALESCE(summary, ''),
			COALESCE(tags, '{}'::text[]),
			content,
			created_at
		FROM posts
		WHERE slug = $1
	`
	var post models.Post
	err := s.pool.QueryRow(ctx, query, slug).Scan(
		&post.ID,
		&post.Author,
		&post.Title,
		&post.Slug,
		&post.Summary,
		&post.Tags,
		&post.Content,
		&post.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get post by slug: %w", err)
	}
	return &post, nil
}
