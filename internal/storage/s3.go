// Package storage generates presigned Amazon S3 URLs for VibeNet's encrypted
// file/image attachments. The Go backend never sees plaintext file bytes and
// never proxies uploads or downloads itself — it only signs short-lived URLs
// that let the browser PUT/GET directly against S3, so the server and any
// database admin can only ever observe ciphertext (see internal/api/upload.go
// for how those bytes get end-to-end encrypted client-side before this is
// ever reached).
//
// Deliberately configured from its own AWS_S3_* environment variables rather
// than the AWS_REGION/AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY vars — those are
// reserved for DynamoDB (see internal/db/dynamodb.go) and resolved via the
// SDK's default credential chain. S3 uses a separate IAM identity, loaded
// explicitly as static credentials so the two never collide or fall back on
// each other.
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

// S3Config holds the connection parameters for the attachments bucket, loaded
// from the AWS_S3_* environment variables (never AWS_REGION/AWS_ACCESS_KEY_ID
// /AWS_SECRET_ACCESS_KEY — see the package doc).
type S3Config struct {
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
		Region:          utils.GetEnv("AWS_S3_REGION", ""),
		AccessKeyID:     utils.GetEnv("AWS_S3_ACCESS_KEY_ID", ""),
		SecretAccessKey: utils.GetEnv("AWS_S3_SECRET_ACCESS_KEY", ""),
		BucketName:      utils.GetEnv("AWS_S3_BUCKET_NAME", ""),
	}
}

// IsConfigured reports whether every field needed to sign a request is set.
func (c S3Config) IsConfigured() bool {
	return c.Region != "" && c.AccessKeyID != "" && c.SecretAccessKey != "" && c.BucketName != ""
}

// PresignClient wraps an S3 presign client with the target bucket name.
type PresignClient struct {
	client *s3.PresignClient
	bucket string
}

// NewPresignClient builds a PresignClient from static S3 credentials — not
// the default credential chain, which would resolve DynamoDB's credentials
// instead (see the package doc). Returns an error if cfg is incomplete;
// callers should treat that as "uploads unavailable", not a fatal boot error.
func NewPresignClient(ctx context.Context, cfg S3Config) (*PresignClient, error) {
	if !cfg.IsConfigured() {
		return nil, fmt.Errorf("s3 is not configured: AWS_S3_REGION, AWS_S3_ACCESS_KEY_ID, AWS_S3_SECRET_ACCESS_KEY, and AWS_S3_BUCKET_NAME are all required")
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

	client := s3.NewFromConfig(awsCfg)
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
