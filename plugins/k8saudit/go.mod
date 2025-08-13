module github.com/falcosecurity/plugins/plugins/k8saudit

go 1.15

require (
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b
	github.com/falcosecurity/plugin-sdk-go v0.8.0
	github.com/iancoleman/orderedmap v0.3.0 // indirect
	github.com/valyala/fastjson v1.6.4
)

replace github.com/valyala/fastjson => github.com/geraldcombs/fastjson v0.0.0-20250801170450-bf39244e60b8
