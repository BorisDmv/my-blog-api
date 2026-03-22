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

// Pool returns the underlying pgxpool.Pool
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
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

	// If context has key "includeDrafts" true, return all, else only published
	includeDrafts, _ := ctx.Value("includeDrafts").(bool)
	var listQuery string
	if includeDrafts {
		listQuery = `
				       SELECT
					       id::text,
					       author,
					       title,
					       slug,
					       COALESCE(summary, ''),
					       COALESCE(tags, '{}'::text[]),
					       status,
					       created_at
				       FROM posts
				       ORDER BY created_at DESC
				       LIMIT $1 OFFSET $2
			       `
	} else {
		listQuery = `
				       SELECT
					       id::text,
					       author,
					       title,
					       slug,
					       COALESCE(summary, ''),
					       COALESCE(tags, '{}'::text[]),
					       status,
					       created_at
				       FROM posts
				       WHERE status = 'published'
				       ORDER BY created_at DESC
				       LIMIT $1 OFFSET $2
			       `
	}
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
			&post.Status,
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
	if includeDrafts {
		if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM posts").Scan(&total); err != nil {
			if err == pgx.ErrNoRows {
				total = 0
			} else {
				return nil, 0, fmt.Errorf("count posts: %w", err)
			}
		}
	} else {
		if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM posts WHERE status = 'published'").Scan(&total); err != nil {
			if err == pgx.ErrNoRows {
				total = 0
			} else {
				return nil, 0, fmt.Errorf("count posts: %w", err)
			}
		}
	}
	return posts, total, nil
}

func (s *Store) SearchPosts(ctx context.Context, query string, limit, offset int) ([]models.PostListItem, int, error) {
	if s.pool == nil {
		return nil, 0, errors.New("db not initialized")
	}

	includeDrafts, _ := ctx.Value("includeDrafts").(bool)
	var searchQuery string
	if includeDrafts {
		searchQuery = `
			       SELECT
				       id::text,
				       author,
				       title,
				       slug,
				       COALESCE(summary, ''),
				       COALESCE(tags, '{}'::text[]),
				       created_at
			       FROM posts
			       WHERE title ILIKE '%' || $1 || '%'
				       OR EXISTS (
					       SELECT 1
					       FROM unnest(tags) tag
					       WHERE tag ILIKE '%' || $1 || '%'
				       )
			       ORDER BY created_at DESC
			       LIMIT $2 OFFSET $3
		       `
	} else {
		searchQuery = `
			       SELECT
				       id::text,
				       author,
				       title,
				       slug,
				       COALESCE(summary, ''),
				       COALESCE(tags, '{}'::text[]),
				       created_at
			       FROM posts
			       WHERE (title ILIKE '%' || $1 || '%' OR EXISTS (
					       SELECT 1
					       FROM unnest(tags) tag
					       WHERE tag ILIKE '%' || $1 || '%'
				       ))
				       AND status = 'published'
			       ORDER BY created_at DESC
			       LIMIT $2 OFFSET $3
		       `
	}
	rows, err := s.pool.Query(ctx, searchQuery, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search posts: %w", err)
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
	if includeDrafts {
		const countQuery = `
			       SELECT COUNT(*)
			       FROM posts
			       WHERE title ILIKE '%' || $1 || '%'
				       OR EXISTS (
					       SELECT 1
					       FROM unnest(tags) tag
					       WHERE tag ILIKE '%' || $1 || '%'
				       )
		       `
		if err := s.pool.QueryRow(ctx, countQuery, query).Scan(&total); err != nil {
			if err == pgx.ErrNoRows {
				total = 0
			} else {
				return nil, 0, fmt.Errorf("count search posts: %w", err)
			}
		}
	} else {
		const countQuery = `
			       SELECT COUNT(*)
			       FROM posts
			       WHERE (title ILIKE '%' || $1 || '%' OR EXISTS (
					       SELECT 1
					       FROM unnest(tags) tag
					       WHERE tag ILIKE '%' || $1 || '%'
				       ))
				       AND status = 'published'
		       `
		if err := s.pool.QueryRow(ctx, countQuery, query).Scan(&total); err != nil {
			if err == pgx.ErrNoRows {
				total = 0
			} else {
				return nil, 0, fmt.Errorf("count search posts: %w", err)
			}
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
			status,
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
		&post.Status,
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
			status,
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
		&post.Status,
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

func (s *Store) CreatePost(ctx context.Context, post models.Post) (*models.Post, error) {
	if s.pool == nil {
		return nil, errors.New("db not initialized")
	}

	const query = `
		INSERT INTO posts (author, title, slug, summary, tags, content, status)
		VALUES ($1, $2, $3, $4, $5, $6, COALESCE(NULLIF($7, ''), 'draft'))
		RETURNING
			id::text,
			author,
			title,
			slug,
			COALESCE(summary, ''),
			COALESCE(tags, '{}'::text[]),
			content,
			status,
			created_at
	`

	var created models.Post
	err := s.pool.QueryRow(
		ctx,
		query,
		post.Author,
		post.Title,
		post.Slug,
		post.Summary,
		post.Tags,
		post.Content,
		post.Status,
	).Scan(
		&created.ID,
		&created.Author,
		&created.Title,
		&created.Slug,
		&created.Summary,
		&created.Tags,
		&created.Content,
		&created.Status,
		&created.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create post: %w", err)
	}

	return &created, nil
}

// User persistence
func (s *Store) CreateUser(ctx context.Context, user models.User) (*models.User, error) {
	if s.pool == nil {
		return nil, errors.New("db not initialized")
	}

	const query = `
		INSERT INTO users (username, password_hash)
		VALUES ($1, $2)
		RETURNING id::text, username, password_hash, created_at
	`

	var created models.User
	err := s.pool.QueryRow(ctx, query, user.Username, user.PasswordHash).Scan(
		&created.ID,
		&created.Username,
		&created.PasswordHash,
		&created.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return &created, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	if s.pool == nil {
		return nil, errors.New("db not initialized")
	}
	const query = `
		SELECT id::text, username, password_hash, created_at
		FROM users
		WHERE username = $1
	`
	var user models.User
	err := s.pool.QueryRow(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get user by username: %w", err)
	}
	return &user, nil
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	if s.pool == nil {
		return nil, errors.New("db not initialized")
	}
	const query = `
		SELECT id::text, username, password_hash, created_at
		FROM users
		WHERE id = $1
	`
	var user models.User
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return &user, nil
}
