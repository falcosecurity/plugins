module github.com/falcosecurity/plugins/cloudtrail

go 1.15

replace github.com/falcosecurity/plugin-sdk-go => ../../../plugin-sdk-go

require github.com/aws/aws-sdk-go v1.40.49

require (
	github.com/aws/aws-sdk-go-v2/config v1.8.2
	github.com/aws/aws-sdk-go-v2/service/sqs v1.9.1
	github.com/falcosecurity/plugin-sdk-go v0.0.0-20210924212122-a5da458809a1
	github.com/valyala/fastjson v1.6.3
)
