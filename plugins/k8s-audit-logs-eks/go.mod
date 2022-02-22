module github.com/falcosecurity/plugins/plugins/k8s-audit-logs-eks

replace github.com/falcosecurity/plugins/share/go/pkg/aws/cloudwatchlogs => /home/ubuntu/plugins/share/go/pkg/aws/cloudwatchlogs

replace github.com/falcosecurity/plugins/share/go/pkg/aws/session => /home/ubuntu/plugins/share/go/pkg/aws/session

replace github.com/falcosecurity/plugins/plugins/k8s-audit-logs/pkg/extractor => /home/ubuntu/plugins/plugins/k8s-audit-logs/pkg/extractor

replace github.com/falcosecurity/plugins/plugins/k8s-audit-logs/pkg/fields => /home/ubuntu/plugins/plugins/k8s-audit-logs/pkg/fields

go 1.17

require (
	github.com/aws/aws-sdk-go v1.43.5
	github.com/falcosecurity/plugin-sdk-go v0.1.0
	github.com/falcosecurity/plugins/plugins/k8s-audit-logs/pkg/extractor v0.0.0-00010101000000-000000000000
	github.com/falcosecurity/plugins/plugins/k8s-audit-logs/pkg/fields v0.0.0-00010101000000-000000000000
	github.com/falcosecurity/plugins/share/go/pkg/aws/cloudwatchlogs v0.0.0-00010101000000-000000000000
)

require (
	github.com/falcosecurity/plugins/share/go/pkg/aws/session v0.0.0-00010101000000-000000000000 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/valyala/fastjson v1.6.3 // indirect
)
