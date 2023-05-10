module github.com/falcosecurity/plugins/plugins/cloudtrail

go 1.15

require (
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b
	github.com/aws/aws-lambda-go v1.34.1
	github.com/aws/aws-sdk-go-v2 v1.16.16
	github.com/aws/aws-sdk-go-v2/config v1.17.7
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.11.33
	github.com/aws/aws-sdk-go-v2/service/s3 v1.27.11
	github.com/aws/aws-sdk-go-v2/service/sqs v1.18.5
	github.com/aws/smithy-go v1.13.3
	github.com/falcosecurity/plugin-sdk-go v0.7.1
	github.com/valyala/fastjson v1.6.3
)
