// Avatar uploads to Supabase Storage's S3-compatible API.
//
// Unlike chat attachments (client-side E2EE, presigned URLs — see s3.go),
// avatar bytes already land on the backend via a multipart form upload, so
// the server uploads them directly and hands back the bucket's public object
// URL. No presigning is needed since the avatars bucket is public.
package storage

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// AvatarStoreConfig holds the connection parameters for Supabase Storage's
// S3-compatible API, loaded from SUPABASE_S3_* environment variables. These
// come from the project's Storage > Settings > S3 Connection panel — a
// separate credential pair from the anon/service_role API keys.
type AvatarStoreConfig struct {
	Endpoint        string // e.g. https://<project-ref>.supabase.co/storage/v1/s3
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	Bucket          string
}

// LoadAvatarStoreConfig builds an AvatarStoreConfig from the environment.
// Fields are left blank when unset rather than erroring — see IsConfigured;
// a deployment without Supabase Storage credentials should still boot, just
// with avatar uploads disabled.
func LoadAvatarStoreConfig() AvatarStoreConfig {
	return AvatarStoreConfig{
		Endpoint:        utils.GetEnv("SUPABASE_S3_ENDPOINT", ""),
		Region:          utils.GetEnv("SUPABASE_S3_REGION", ""),
		AccessKeyID:     utils.GetEnv("SUPABASE_S3_ACCESS_KEY_ID", ""),
		SecretAccessKey: utils.GetEnv("SUPABASE_S3_SECRET_ACCESS_KEY", ""),
		Bucket:          utils.GetEnv("SUPABASE_S3_BUCKET", "avatars"),
	}
}

// IsConfigured reports whether every field needed to talk to the bucket is set.
func (c AvatarStoreConfig) IsConfigured() bool {
	return c.Endpoint != "" && c.Region != "" && c.AccessKeyID != "" && c.SecretAccessKey != "" && c.Bucket != ""
}

// AvatarStore uploads avatar images directly to a public Supabase Storage
// bucket and returns a stable public URL for each — no presigning, since the
// bucket is public and the backend (not the browser) already holds the bytes.
type AvatarStore struct {
	client    *s3.Client
	bucket    string
	publicURL string // e.g. https://<project-ref>.supabase.co/storage/v1/object/public
}

// NewAvatarStore builds an AvatarStore from cfg. Returns an error if cfg is
// incomplete; callers should treat that as "avatar uploads unavailable", not
// a fatal boot error — the same graceful-degradation pattern as NewPresignClient.
func NewAvatarStore(ctx context.Context, cfg AvatarStoreConfig) (*AvatarStore, error) {
	if !cfg.IsConfigured() {
		return nil, fmt.Errorf("supabase avatar storage is not configured: SUPABASE_S3_ENDPOINT, SUPABASE_S3_REGION, SUPABASE_S3_ACCESS_KEY_ID, SUPABASE_S3_SECRET_ACCESS_KEY, and SUPABASE_S3_BUCKET are all required")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("load supabase s3 aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.Endpoint)
		// Supabase's S3-compatible API isn't *.amazonaws.com virtual-hosted
		// style — it requires path-style bucket addressing.
		o.UsePathStyle = true
	})

	// The public object URL lives under a different path than the S3 API
	// endpoint: swap "/storage/v1/s3" for "/storage/v1/object/public".
	publicURL := strings.TrimSuffix(cfg.Endpoint, "/storage/v1/s3") + "/storage/v1/object/public"

	return &AvatarStore{client: client, bucket: cfg.Bucket, publicURL: publicURL}, nil
}

// Upload writes body under key in the avatars bucket and returns its public
// URL. contentType is set on the object so browsers render it inline instead
// of forcing a download.
func (a *AvatarStore) Upload(ctx context.Context, key string, body io.Reader, contentType string) (string, error) {
	_, err := a.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(a.bucket),
		Key:         aws.String(key),
		Body:        body,
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return "", fmt.Errorf("upload avatar: %w", err)
	}
	return fmt.Sprintf("%s/%s/%s", a.publicURL, a.bucket, key), nil
}

// Delete removes a previously uploaded avatar object. Callers use this for
// best-effort cleanup when a DB write fails after a successful upload.
func (a *AvatarStore) Delete(ctx context.Context, key string) error {
	_, err := a.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(a.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("delete avatar: %w", err)
	}
	return nil
}
