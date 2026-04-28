module github.com/falcosecurity/plugins/plugins/k8saudit-aks

go 1.25.0

require (
	github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs v1.4.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.6.4
	github.com/falcosecurity/plugin-sdk-go v0.8.3
	github.com/falcosecurity/plugins/plugins/k8saudit v0.16.1
	github.com/falcosecurity/plugins/shared/go/azure/eventhub v0.0.0-20250617140945-5d23e77c8bbd
	github.com/invopop/jsonschema v0.14.0
	golang.org/x/time v0.15.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.20.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.2 // indirect
	github.com/Azure/go-amqp v1.4.0 // indirect
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/iancoleman/orderedmap v0.3.0 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.2 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/text v0.31.0 // indirect
)

replace github.com/falcosecurity/plugins/shared/go/azure/eventhub => ../../shared/go/azure/eventhub

replace github.com/valyala/fastjson => github.com/geraldcombs/fastjson v0.0.0-20250801170450-bf39244e60b8
