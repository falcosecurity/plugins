module github.com/falcosecurity/plugins/plugins/k8saudit-aks

go 1.21.3

require (
	github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs v1.2.3
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.6.0
	github.com/falcosecurity/plugin-sdk-go v0.7.4
	github.com/falcosecurity/plugins/plugins/k8saudit v0.11.0
	github.com/falcosecurity/plugins/shared/go/azure/eventhub v0.0.0-20250117093332-1dc8b8272f85
	github.com/invopop/jsonschema v0.13.0
	golang.org/x/time v0.9.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.17.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.10.0 // indirect
	github.com/Azure/go-amqp v1.3.0 // indirect
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/iancoleman/orderedmap v0.3.0 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/falcosecurity/plugins/shared/go/azure/eventhub => ../../shared/go/azure/eventhub
