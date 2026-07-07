package db

import (
	"context"
	"fmt"
	"log"

	"github.com/ChamathDilshanC/VibeNet-backend/pkg/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// DynamoDBConfig holds the connection parameters for the Amazon DynamoDB messages table.
type DynamoDBConfig struct {
	Region    string
	TableName string
	Endpoint  string
}

// LoadDynamoDBConfig builds a DynamoDBConfig from environment variables.
func LoadDynamoDBConfig() DynamoDBConfig {
	return DynamoDBConfig{
		Region:    utils.GetEnv("AWS_REGION", "us-east-1"),
		TableName: utils.GetEnv("DYNAMODB_MESSAGES_TABLE", "vibenet-messages"),
		Endpoint:  utils.GetEnv("DYNAMODB_ENDPOINT", ""),
	}
}

// ConnectDynamoDB creates an AWS SDK v2 DynamoDB client using the default credential chain.
// When DYNAMODB_ENDPOINT is set, the client targets a local or custom endpoint (e.g. DynamoDB Local).
func ConnectDynamoDB(ctx context.Context, cfg DynamoDBConfig) (*dynamodb.Client, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	var client *dynamodb.Client
	if cfg.Endpoint != "" {
		client = dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	} else {
		client = dynamodb.NewFromConfig(awsCfg)
	}

	return client, nil
}

// PingDynamoDB verifies connectivity by describing the configured messages table.
func PingDynamoDB(ctx context.Context, client *dynamodb.Client, tableName string) error {
	_, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		return fmt.Errorf("describe dynamodb table %q: %w", tableName, err)
	}
	return nil
}

// MessagesTableName returns the DynamoDB table name used for encrypted chat history.
func MessagesTableName(cfg DynamoDBConfig) string {
	return cfg.TableName
}

// CloseDynamoDB is a no-op placeholder for API symmetry with ClosePostgres.
// The AWS SDK v2 DynamoDB client does not require explicit shutdown.
func CloseDynamoDB(_ *dynamodb.Client) {
	log.Println("dynamodb client released")
}
