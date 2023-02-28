package s3

import (
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

const (
	S3BucketEnv = "AWS_S3_BUCKET"
	S3PrefixEnv = "AWS_S3_PREFIX"
	S3RegionEnv = "AWS_S3_REGION"
)

func DoUploadToS3(buildType string) error {

	var s3prefix, s3bucket, s3region string
	var found bool

	if s3prefix, found = os.LookupEnv(S3PrefixEnv); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", S3PrefixEnv)
	}

	if s3bucket, found = os.LookupEnv(S3BucketEnv); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", S3BucketEnv)
	}

	if s3region, found = os.LookupEnv(S3RegionEnv); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", S3RegionEnv)
	}

	if buildType != "stable" && buildType != "dev" {
		return fmt.Errorf("invalid build version %s", buildType)
	}

	s3s, err := session.NewSession(&aws.Config{Region: aws.String(s3region)})
	if err != nil {
		log.Fatal(err)
	}

	key := path.Join(s3prefix, buildType)

	outDir := os.DirFS("../../../output")
	fs.WalkDir(outDir, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Fatal(err)
		}

		if filepath.Ext(path) == ".tar.gz" {
			if err = s3UploadFile(s3s, s3bucket, path, key); err != nil {
				return fmt.Errorf("could not upload %s to bucket %s, key %s: %w", path, s3bucket, key, err)
			}
		}

		return nil
	})

	return nil
}

func s3UploadFile(session *session.Session, bucket string, filePath string, key string) error {
	upFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer upFile.Close()

	upFileInfo, _ := upFile.Stat()
	fileSize := upFileInfo.Size()
	fileBuffer := make([]byte, fileSize)
	upFile.Read(fileBuffer)

	_, err = s3.New(session).PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(bucket),
		Key:                  aws.String(key),
		Body:                 bytes.NewReader(fileBuffer),
		ContentLength:        aws.Int64(fileSize),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
	})

	return err
}
