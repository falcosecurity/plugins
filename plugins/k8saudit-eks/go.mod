module github.com/falcosecurity/plugins/plugins/k8saudit-eks

go 1.25.5

require (
	github.com/falcosecurity/plugin-sdk-go v0.8.3
	github.com/falcosecurity/plugins/plugins/k8saudit v0.17.0
	github.com/falcosecurity/plugins/shared/go/aws/cloudwatchlogs v0.0.0-20250617140945-5d23e77c8bbd
	github.com/falcosecurity/plugins/shared/go/aws/config v0.0.0-20250617140945-5d23e77c8bbd
	github.com/invopop/jsonschema v0.14.0
)

require (
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b // indirect
	github.com/aws/aws-sdk-go-v2 v1.41.6 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.8 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.16 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.15 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.22 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.22 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.22 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.68.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.42.0 // indirect
	github.com/aws/smithy-go v1.25.1 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/iancoleman/orderedmap v0.3.0 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.2 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

replace (
	github.com/falcosecurity/plugins/shared/go/aws/cloudwatchlogs => ../../shared/go/aws/cloudwatchlogs
	github.com/falcosecurity/plugins/shared/go/aws/config => ../../shared/go/aws/config
	github.com/valyala/fastjson => github.com/geraldcombs/fastjson v0.0.0-20250801170450-bf39244e60b8
)
