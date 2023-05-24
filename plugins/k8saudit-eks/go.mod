module github.com/falcosecurity/plugins/plugins/k8saudit-eks

go 1.17

require (
	github.com/falcosecurity/plugin-sdk-go v0.7.1
	github.com/falcosecurity/plugins/plugins/k8saudit v0.0.0-20221013103017-8f1a599ad3eb
	github.com/falcosecurity/plugins/shared/go/aws/cloudwatchlogs v0.0.0-20221004205118-1db426496417
	github.com/falcosecurity/plugins/shared/go/aws/session v0.0.0-20220824115709-c23dc2a4657e
	github.com/invopop/jsonschema v0.6.0
)

require (
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b // indirect
	github.com/aws/aws-sdk-go v1.44.112 // indirect
	github.com/iancoleman/orderedmap v0.0.0-20190318233801-ac98e3ecb4b0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/valyala/fastjson v1.6.3 // indirect
)
