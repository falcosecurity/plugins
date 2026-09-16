module github.com/falcosecurity/plugins/plugins/k8saudit-aks

go 1.26.0

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.23.1
	github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs v1.4.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.8.1
	github.com/falcosecurity/plugin-sdk-go v0.8.3
	github.com/falcosecurity/plugins/plugins/k8saudit v0.18.0
	github.com/falcosecurity/plugins/shared/go/azure/eventhub v0.0.0-20250617140945-5d23e77c8bbd
	github.com/falcosecurity/plugins/shared/go/azure/identity v0.0.0-00010101000000-000000000000
	github.com/invopop/jsonschema v0.14.0
	github.com/segmentio/kafka-go v0.4.51
	github.com/valyala/fastjson v1.6.4
	golang.org/x/time v0.16.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.14.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.12.0 // indirect
	github.com/Azure/go-amqp v1.4.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.8.0 // indirect
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b // indirect
	github.com/apache/arrow-go/v18 v18.7.0 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/flatbuffers v25.12.19+incompatible // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/iancoleman/orderedmap v0.3.0 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.28 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.2 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/exp v0.0.0-20260813180055-c1d0aacb2297 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

replace github.com/falcosecurity/plugins/shared/go/azure/eventhub => ../../shared/go/azure/eventhub

replace github.com/falcosecurity/plugins/shared/go/azure/identity => ../../shared/go/azure/identity

replace github.com/valyala/fastjson => github.com/geraldcombs/fastjson v0.0.0-20250801170450-bf39244e60b8
