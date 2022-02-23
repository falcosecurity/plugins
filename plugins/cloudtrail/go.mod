module github.com/falcosecurity/plugins/cloudtrail

go 1.15

require github.com/aws/aws-sdk-go v1.42.12

require (
	github.com/aws/aws-sdk-go-v2/config v1.10.2
	github.com/aws/aws-sdk-go-v2/service/sqs v1.12.1
	github.com/falcosecurity/plugin-sdk-go v0.0.0-20211125012426-11baaa45581c
	github.com/oschwald/maxminddb-golang v1.8.0 // indirect
	github.com/valyala/fastjson v1.6.3
)
