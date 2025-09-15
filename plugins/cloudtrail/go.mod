module github.com/falcosecurity/plugins/plugins/cloudtrail

go 1.22

require (
	github.com/aws/aws-lambda-go v1.49.0
	github.com/aws/aws-sdk-go-v2 v1.39.0
	github.com/aws/aws-sdk-go-v2/config v1.29.16
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.17.79
	github.com/aws/aws-sdk-go-v2/service/s3 v1.88.1
	github.com/aws/aws-sdk-go-v2/service/sqs v1.38.7
	github.com/aws/smithy-go v1.23.0
	github.com/falcosecurity/plugin-sdk-go v0.8.3
	github.com/invopop/jsonschema v0.13.0
	github.com/valyala/fastjson v1.6.4
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.1 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.69 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.8.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.21 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/valyala/fastjson => github.com/geraldcombs/fastjson v0.0.0-20250801170450-bf39244e60b8
