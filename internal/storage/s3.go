// Package storage generates presigned URLs against Supabase Storage's
// S3-compatible API for VibeNet's encrypted file/image attachments. The Go
// backend never sees plaintext file bytes and never proxies uploads or
// downloads itself — it only signs short-lived URLs that let the browser
// PUT/GET directly against the bucket, so the server and any database admin
// can only ever observe ciphertext (see internal/api/upload.go for how those
// bytes get end-to-end encrypted client-side before this is ever reached).
//
// Shares its SUPABASE_S3_* endpoint/region/credentials with the avatar store
// (see avatars.go) — both are the same project-scoped Supabase S3 access key,
// differing only in which bucket they target. The attachments bucket must
// stay private (unlike the public avatars bucket): reads go through
// PresignGetURL, never a public URL, since attachments are ciphertext meant
// only for the intended recipient.
package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Config holds the connection parameters for the attachments bucket. The
// endpoint/region/credentials are the same Supabase S3 access key used for
// avatars (see AvatarStoreConfig); only the bucket name differs.
type S3Config struct {
	Endpoint        string // e.g. https://<project-ref>.supabase.co/storage/v1/s3
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	BucketName      string
}

// LoadS3Config builds an S3Config from the environment. Fields are left blank
// when unset rather than erroring — see IsConfigured; a fresh clone without S3
// credentials should still boot, just with file uploads disabled.
func LoadS3Config() S3Config {
	return S3Config{
		Endpoint:        utils.GetEnv("SUPABASE_S3_ENDPOINT", ""),
		Region:          utils.GetEnv("SUPABASE_S3_REGION", ""),
		AccessKeyID:     utils.GetEnv("SUPABASE_S3_ACCESS_KEY_ID", ""),
		SecretAccessKey: utils.GetEnv("SUPABASE_S3_SECRET_ACCESS_KEY", ""),
		BucketName:      utils.GetEnv("SUPABASE_S3_ATTACHMENTS_BUCKET", "chat-attachments"),
	}
}

// IsConfigured reports whether every field needed to sign a request is set.
func (c S3Config) IsConfigured() bool {
	return c.Endpoint != "" && c.Region != "" && c.AccessKeyID != "" && c.SecretAccessKey != "" && c.BucketName != ""
}

// PresignClient wraps an S3 presign client with the target bucket name.
type PresignClient struct {
	client *s3.PresignClient
	bucket string
}

// NewPresignClient builds a PresignClient from static Supabase S3 credentials.
// Returns an error if cfg is incomplete; callers should treat that as
// "uploads unavailable", not a fatal boot error.
func NewPresignClient(ctx context.Context, cfg S3Config) (*PresignClient, error) {
	if !cfg.IsConfigured() {
		return nil, fmt.Errorf("s3 is not configured: SUPABASE_S3_ENDPOINT, SUPABASE_S3_REGION, SUPABASE_S3_ACCESS_KEY_ID, SUPABASE_S3_SECRET_ACCESS_KEY, and SUPABASE_S3_ATTACHMENTS_BUCKET are all required")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("load s3 aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.Endpoint)
		// Supabase's S3-compatible API isn't *.amazonaws.com virtual-hosted
		// style — it requires path-style bucket addressing.
		o.UsePathStyle = true
	})
	return &PresignClient{
		client: s3.NewPresignClient(client),
		bucket: cfg.BucketName,
	}, nil
}

// PresignPutURL signs a short-lived PUT URL for the given key. Content-Type is
// deliberately left unset on the signed request — the uploaded bytes are
// already-encrypted ciphertext with no meaningful MIME type of their own, and
// leaving it unsigned means the browser's PUT doesn't have to match a pinned
// header exactly to avoid a SignatureDoesNotMatch.
func (p *PresignClient) PresignPutURL(ctx context.Context, key string, expires time.Duration) (string, error) {
	req, err := p.client.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(expires))
	if err != nil {
		return "", fmt.Errorf("presign put url: %w", err)
	}
	return req.URL, nil
}

// PresignGetURL signs a short-lived GET URL for the given key. Generated fresh
// on demand each time a recipient renders an attachment (see
// GET /api/upload/download-url) rather than stored once, so chat history
// keeps working long after any single signed URL would have expired — the
// bucket stays fully private with no public-read object ACL required.
func (p *PresignClient) PresignGetURL(ctx context.Context, key string, expires time.Duration) (string, error) {
	req, err := p.client.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(expires))
	if err != nil {
		return "", fmt.Errorf("presign get url: %w", err)
	}
	return req.URL, nil
}
