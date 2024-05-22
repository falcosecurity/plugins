package kafka

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/segmentio/kafka-go"
)

const (
	PluginID          uint32 = 18
	PluginName               = "kafka"
	PluginDescription        = "Read events from Kafka topics into Falco"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.1.1"
	PluginEventSource        = "kafka"
)

// PluginConfig represents the kafka configuration
// we collect during the initialization phase of the plugin.
type PluginConfig struct {
	Brokers   []string  `json:"brokers" jsonschema:"title=Kafka Brokers,description=The list of Kafka brokers to consume messages from."`
	GroupId   string    `json:"groupId" jsonschema:"title=Group ID,description=The consumer group identifier."`
	Topics    []string  `json:"topics" jsonschema:"title=Kafka Brokers,description=The topics to consume from."`
	TlsConfig TlsConfig `json:"tlsConfig" jsonschema:"title=TLS Config,description=Configuration for TLS encryption."`
}

// TlsConfig represents the information
// needed to establish an mTLS connection with the Kafka server
type TlsConfig struct {
	CaCertPath   string `json:"caCertPath" jsonschema:"title=Ca Cert Path,description=Path to the Kafka server's public certificate."`
	UserCertPath string `json:"userCertPath" jsonschema:"title=User Cert Path,description=Path to the user's public certificate."`
	UserKeyPath  string `json:"userKeyPath" jsonschema:"title=User Key Path,description=Path to the user's private key."`
}

// Plugin creates a connection between Kafka and Falco, exposing the
// messages on a set of topics to Falco's processing engine.
type Plugin struct {
	plugins.BasePlugin

	pluginConfig PluginConfig
	reader       *kafka.Reader
}

func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          PluginID,
		Name:        PluginName,
		Description: PluginDescription,
		Contact:     PluginContact,
		Version:     PluginVersion,
		EventSource: PluginEventSource,
	}
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true,
		AllowAdditionalProperties:  true,
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (p *Plugin) Init(config string) (err error) {
	if len(config) != 0 {
		err = json.Unmarshal([]byte(config), &p.pluginConfig)
	}

	return
}

func (p *Plugin) Open(params string) (source.Instance, error) {
	dailer, err := p.newDialer()

	if err != nil {
		return nil, err
	}

	p.reader = kafka.NewReader(kafka.ReaderConfig{
		Brokers:     p.pluginConfig.Brokers,
		GroupID:     p.pluginConfig.GroupId,
		GroupTopics: p.pluginConfig.Topics,
		Dialer:      dailer,
	})

	kafkaEvents := make(chan source.PushEvent)
	ctx, cancel := context.WithCancel(context.Background())

	push := func(ctx context.Context) {
		defer close(kafkaEvents)

		for {
			msg, err := p.reader.ReadMessage(ctx)

			if err != nil {
				kafkaEvents <- source.PushEvent{Err: err}
				return
			}

			kafkaEvents <- source.PushEvent{Data: msg.Value, Timestamp: msg.Time}
		}
	}

	go push(ctx)
	return source.NewPushInstance(
		kafkaEvents,
		source.WithInstanceClose(cancel),
		source.WithInstanceTimeout(10*time.Millisecond))
}

func (p *Plugin) Destroy() {
	if p.reader == nil {
		return
	}

	if err := p.reader.Close(); err != nil {
		panic(err)
	}
}

func (p *Plugin) newDialer() (*kafka.Dialer, error) {
	if len(p.pluginConfig.TlsConfig.CaCertPath) == 0 {
		return nil, nil
	}

	caPEM, err := os.ReadFile(p.pluginConfig.TlsConfig.CaCertPath)

	if err != nil {
		return nil, err
	}

	certPEM, err := os.ReadFile(p.pluginConfig.TlsConfig.UserCertPath)

	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(p.pluginConfig.TlsConfig.UserCertPath)

	if err != nil {
		return nil, err
	}

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)

	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()

	if ok := caCertPool.AppendCertsFromPEM(caPEM); !ok {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false,
	}

	return &kafka.Dialer{TLS: tlsConfig}, nil
}
