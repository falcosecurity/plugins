module github.com/falcosecurity/plugins/plugins/k8saudit-aks

go 1.23.0

toolchain go1.24.1

require (
	github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs v1.3.1
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.6.0
	github.com/falcosecurity/plugin-sdk-go v0.7.4
	github.com/falcosecurity/plugins/plugins/k8saudit v0.12.0
	github.com/falcosecurity/plugins/shared/go/azure/eventhub v0.0.0-20250317101106-29866234603d
	github.com/invopop/jsonschema v0.13.0
	golang.org/x/time v0.11.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.17.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.10.0 // indirect
	github.com/Azure/go-amqp v1.4.0 // indirect
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/iancoleman/orderedmap v0.3.0 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	golang.org/x/net v0.37.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/falcosecurity/plugins/shared/go/azure/eventhub => ../../shared/go/azure/eventhub
