module github.com/falcosecurity/plugins/plugins/k8saudit-eks

go 1.25.5

require (
	github.com/falcosecurity/plugin-sdk-go v0.8.3
	github.com/falcosecurity/plugins/plugins/k8saudit v0.16.1
	github.com/falcosecurity/plugins/shared/go/aws/cloudwatchlogs v0.0.0-20250617140945-5d23e77c8bbd
	github.com/falcosecurity/plugins/shared/go/aws/config v0.0.0-20250617140945-5d23e77c8bbd
	github.com/invopop/jsonschema v0.13.0
)

require (
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b // indirect
	github.com/aws/aws-sdk-go-v2 v1.41.5 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.8 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.14 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.14 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.68.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.10 // indirect
	github.com/aws/smithy-go v1.24.3 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/iancoleman/orderedmap v0.3.0 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/falcosecurity/plugins/shared/go/aws/cloudwatchlogs => ../../shared/go/aws/cloudwatchlogs
	github.com/falcosecurity/plugins/shared/go/aws/config => ../../shared/go/aws/config
	github.com/valyala/fastjson => github.com/geraldcombs/fastjson v0.0.0-20250801170450-bf39244e60b8
)
