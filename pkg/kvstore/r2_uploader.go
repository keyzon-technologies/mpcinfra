package kvstore

import (
	"bytes"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// R2Uploader uploads encrypted backup files to Cloudflare R2 using the S3-compatible API.
type R2Uploader struct {
	client *s3.Client
	bucket string
	prefix string // object key prefix, e.g. "backups/node0/"
}

// NewR2Uploader creates an R2Uploader.
//   - accountID: Cloudflare account ID (used to build the endpoint URL)
//   - accessKeyID / secretAccessKey: R2 API token credentials
//   - bucket: R2 bucket name
//   - prefix: optional object key prefix (e.g. "node0/"); leave empty for root
func NewR2Uploader(accountID, accessKeyID, secretAccessKey, bucket, prefix string) (*R2Uploader, error) {
	if accountID == "" || accessKeyID == "" || secretAccessKey == "" || bucket == "" {
		return nil, fmt.Errorf("r2: accountID, accessKeyID, secretAccessKey and bucket are required")
	}

	endpoint := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)

	cfg := aws.Config{
		Region:      "auto",
		Credentials: credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""),
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	return &R2Uploader{
		client: client,
		bucket: bucket,
		prefix: prefix,
	}, nil
}

// Upload sends the encrypted backup file to R2. The object key is <prefix><filename>.
func (u *R2Uploader) Upload(ctx context.Context, filename string, data []byte) error {
	key := u.prefix + filename
	_, err := u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(u.bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
		ContentType:   aws.String("application/octet-stream"),
	})
	if err != nil {
		return fmt.Errorf("r2 upload %q: %w", key, err)
	}
	return nil
}
