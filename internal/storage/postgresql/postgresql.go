package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	IssuedAt  time.Time
	ExpiresAt time.Time
	IssuedIP  string
	IsUsed    bool
	CreatedAt time.Time
}

type Storage struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    issued_ip INET NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);`

func New(connStr string) (*Storage, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveRefreshToken(ctx context.Context, token RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, issued_at, expires_at, issued_ip)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := s.db.ExecContext(ctx, query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.IssuedAt,
		token.ExpiresAt,
		token.IssuedIP,
	)
	return err
}

func (s *Storage) GetRefreshToken(ctx context.Context, tokenID uuid.UUID) (*RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, issued_at, expires_at, issued_ip, is_used, created_at
		FROM refresh_tokens
		WHERE id = $1`

	var token RefreshToken
	err := s.db.QueryRowContext(ctx, query, tokenID).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.IssuedAt,
		&token.ExpiresAt,
		&token.IssuedIP,
		&token.IsUsed,
		&token.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, errors.New("refresh token not found")
	}
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *Storage) MarkTokenAsUsed(ctx context.Context, tokenID uuid.UUID) error {
	query := `UPDATE refresh_tokens SET is_used = true WHERE id = $1`
	result, err := s.db.ExecContext(ctx, query, tokenID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("refresh token not found")
	}
	return nil
}
