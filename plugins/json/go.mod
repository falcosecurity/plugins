module github.com/falcosecurity/plugins/json

go 1.15

replace github.com/falcosecurity/plugin-sdk-go => ../../../plugin-sdk-go

require (
	github.com/falcosecurity/plugin-sdk-go v0.0.2-plugin-system-api-additions
	github.com/valyala/fastjson v1.6.3
)
