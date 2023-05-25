/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/bluele/gcache"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

// LogEvent describes a single logged action or "event" that is performed by a set of actors for a set of targets.
type LogEvent struct {
	UUID            string `json:"uuid"`
	Published       string `json:"published"`
	EventType       string `json:"eventType"`
	Version         string `json:"version"`
	Severity        string `json:"severity"`
	LegacyEventType string `json:"legacyEventType,omitempty"`
	DisplayMessage  string `json:"displayMessage"`
	Actor           struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		AlternateID string `json:"alternateId,omitempty"`
		DisplayName string `json:"displayName,omitempty"`
	} `json:"actor"`
	Client struct {
		UserAgent struct {
			OS           string `json:"os,omitempty"`
			Browser      string `json:"browser,omitempty"`
			RawUserAgent string `json:"rawUserAgent,omitempty"`
		} `json:"userAgent,omitempty"`
		GeographicalContext struct {
			Geolocation struct {
				Lat float64 `json:"lat,omitempty"`
				Lon float64 `json:"lonDe,omitempty"`
			} `json:"geolocation,omitempty"`
			City       string `json:"city,omitempty"`
			State      string `json:"state,omitempty"`
			Country    string `json:"country,omitempty"`
			PostalCode string `json:"postalCode,omitempty"`
		} `json:"geographicalContext,omitempty"`
		Zone      string `json:"zone,omitempty"`
		IPAddress string `json:"ipAddress,omitempty"`
		Device    string `json:"device,omitempty"`
		ID        string `json:"id,omitempty"`
	} `json:"client,omitempty"`
	Outcome struct {
		Result string `json:"result"`
		Reason string `json:"reason,omitempty"`
	} `json:"outcome,omitempty"`
	Target []struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		AlternateID string `json:"alternateId,omitempty"`
		DisplayName string `json:"displayName,omitempty"`
	} `json:"target,omitempty"`
	Transaction struct {
		Type string `json:"type,omitempty"`
		ID   string `json:"id,omitempty"`
	} `json:"transaction"`
	DebugContext struct {
		DebugData struct {
			RequestURI        string `json:"requestUri"`
			OriginalPrincipal struct {
				ID          string `json:"id,omitempty"`
				Type        string `json:"type,omitempty"`
				AlternateID string `json:"alternateId,omitempty"`
				DisplayName string `json:"displayName,omitempty"`
			} `json:"originalPrincipal,omitempty"`
		} `json:"debugData,omitempty"`
	} `json:"debugContext,omitempty"`
	AuthenticationContext struct {
		AuthenticationStep int    `json:"authenticationStep,omitempty"`
		ExternalSessionID  string `json:"externalSessionId,omitempty"`
	} `json:"authenticationContext,omitempty"`
	SecurityContext struct {
		AsNumber int    `json:"asNumber,omitempty"`
		AsOrg    string `json:"asOrg,omitempty"`
		ISP      string `json:"isp,omitempty"`
		Domain   string `json:"domain,omitempty"`
	} `json:"securityContext,omitempty"`
}

// Plugin represents our plugin
type Plugin struct {
	plugins.BasePlugin
	APIToken         string `json:"api_token" jsonschema:"title=API token,description=API Token"`
	Organization     string `json:"organization" jsonschema:"title=Organization,description=Your Okta organization"`
	CacheExpiration  uint64 `json:"cache_expiration" jsonschema:"title=Cache Expiration,description=TTL in seconds for keys in cache for MFA events (default: 600)"`
	CacheUserMaxSize uint64 `json:"cache_usermaxsize" jsonschema:"title=Cache User Max Size,description=Max size by user for the cache (default: 200)"`
	lastLogEvent     LogEvent
	lastEventNum     uint64
	cache            gcache.Cache
}

// PluginInstance represents a opened stream based on our Plugin
type PluginInstance struct {
	source.BaseInstance
	client      *http.Client
	request     *http.Request
	cancel      context.CancelFunc
	lastReqTime time.Time
}

const oktaBaseURL string = "okta.com/api/v1/logs"

// Info displays information of the plugin to Falco plugin framework
func (oktaPlugin *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          7,
		Name:        "okta",
		Description: "Okta Log Events",
		Contact:     "github.com/falcosecurity/plugins/",
		Version:     "0.8.0",
		EventSource: "okta",
	}
}

// InitSchema exports the json schema for parameters
func (oktaPlugin *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&Plugin{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (oktaPlugin *Plugin) Init(config string) error {
	oktaPlugin.CacheExpiration = 84600
	oktaPlugin.CacheUserMaxSize = 200
	err := json.Unmarshal([]byte(config), &oktaPlugin)
	if err != nil {
		return err
	}
	oktaPlugin.cache = gcache.New(10000).LFU().Build()
	return nil
}

// Fields exposes to Falco plugin framework all availables fields for this plugin
func (oktaPlugin *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "okta.app", Desc: "Application"},
		{Type: "string", Name: "okta.org", Desc: "Organization"},
		{Type: "string", Name: "okta.evt.type", Desc: "Event Type"},
		{Type: "string", Name: "okta.evt.legacytype", Desc: "Event Legacy Type"},
		{Type: "string", Name: "okta.severity", Desc: "Severity"},
		{Type: "string", Name: "okta.message", Desc: "Message"},
		{Type: "string", Name: "okta.published", Desc: "Event Source Timestamp"},
		{Type: "string", Name: "okta.actor.id", Desc: "Actor ID"},
		{Type: "string", Name: "okta.actor.Type", Desc: "Actor Type"},
		{Type: "string", Name: "okta.actor.alternateid", Desc: "Actor Alternate ID"},
		{Type: "string", Name: "okta.actor.name", Desc: "Actor Display Name"},
		{Type: "string", Name: "okta.client.zone", Desc: "Client Zone"},
		{Type: "string", Name: "okta.client.ip", Desc: "Client IP Address"},
		{Type: "string", Name: "okta.client.device", Desc: "Client Device"},
		{Type: "string", Name: "okta.client.id", Desc: "Client ID"},
		{Type: "string", Name: "okta.client.geo.city", Desc: "Client Geographical City"},
		{Type: "string", Name: "okta.client.geo.state", Desc: "Client Geographical State"},
		{Type: "string", Name: "okta.client.geo.country", Desc: "Client Geographical Country"},
		{Type: "string", Name: "okta.client.geo.postalcode", Desc: "Client Geographical Postal Code"},
		{Type: "string", Name: "okta.client.geo.lat", Desc: "Client Geographical Latitude"},
		{Type: "string", Name: "okta.client.geo.lon", Desc: "Client Geographical Longitude"},
		{Type: "string", Name: "okta.useragent.os", Desc: "Useragent OS"},
		{Type: "string", Name: "okta.useragent.browser", Desc: "Useragent Browser"},
		{Type: "string", Name: "okta.useragent.raw", Desc: "Raw Useragent"},
		{Type: "string", Name: "okta.result", Desc: "Outcome Result"},
		{Type: "string", Name: "okta.reason", Desc: "Outcome Reason"},
		{Type: "string", Name: "okta.transaction.id", Desc: "Transaction ID"},
		{Type: "string", Name: "okta.transaction.type", Desc: "Transaction Type"},
		{Type: "string", Name: "okta.requesturi", Desc: "Request URI"},
		{Type: "string", Name: "okta.principal.id", Desc: "Principal ID"},
		{Type: "string", Name: "okta.principal.alternateid", Desc: "Principal Alternate ID"},
		{Type: "string", Name: "okta.principal.type", Desc: "Principal Type"},
		{Type: "string", Name: "okta.principal.name", Desc: "Principal Name"},
		{Type: "string", Name: "okta.authentication.step", Desc: "Authentication Step"},
		{Type: "string", Name: "okta.authentication.sessionid", Desc: "External Session ID"},
		{Type: "uint64", Name: "okta.security.asnumber", Desc: "Security AS Number"},
		{Type: "string", Name: "okta.security.asorg", Desc: "Security AS Org"},
		{Type: "string", Name: "okta.security.isp", Desc: "Security ISP"},
		{Type: "string", Name: "okta.security.domain", Desc: "Security Domain"},
		{Type: "string", Name: "okta.target.user.id", Desc: "Target User ID"},
		{Type: "string", Name: "okta.target.user.alternateid", Desc: "Target User Alternate ID"},
		{Type: "string", Name: "okta.target.user.name", Desc: "Target User Name"},
		{Type: "string", Name: "okta.target.group.id", Desc: "Target Group ID"},
		{Type: "string", Name: "okta.target.group.alternateid", Desc: "Target Group Alternate ID"},
		{Type: "string", Name: "okta.target.group.name", Desc: "Target Group Name"},
		{Type: "uint64", Name: "okta.mfa.failure.countlast", Desc: "Count of MFA failures in last seconds", Arg: sdk.FieldEntryArg{IsRequired: true, IsIndex: true}},
		{Type: "uint64", Name: "okta.mfa.deny.countlast", Desc: "Count of MFA denies in last seconds", Arg: sdk.FieldEntryArg{IsRequired: true, IsIndex: true}},
	}
}

// Extract allows Falco plugin framework to get values for all available fields
func (oktaPlugin *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	data := oktaPlugin.lastLogEvent

	if evt.EventNum() != oktaPlugin.lastEventNum {
		rawData, err := ioutil.ReadAll(evt.Reader())
		if err != nil {
			return err
		}

		err = json.Unmarshal(rawData, &data)
		if err != nil {
			return err
		}

		oktaPlugin.lastLogEvent = data
		oktaPlugin.lastEventNum = evt.EventNum()

		if data.EventType == "user.mfa.okta_verify.deny_push" || (data.EventType == "user.authentication.auth_via_mfa" && data.Outcome.Result == "FAILURE") {
			key := data.EventType + ":" + data.Actor.ID
			valueList := []uint64{}
			value, err := oktaPlugin.cache.Get(key)
			if err == nil {
				if value != nil {
					valueList = value.([]uint64)
				}
			}
			valueList = append(valueList, evt.Timestamp())
			if uint64(len(valueList)) > oktaPlugin.CacheUserMaxSize {
				valueList = valueList[1:]
			}
			err = oktaPlugin.cache.SetWithExpire(key, valueList, time.Duration(oktaPlugin.CacheExpiration)*time.Second)
			if err != nil {
				return err
			}
		}
	}

	switch req.Field() {
	case "okta.app":
		if strings.HasPrefix(data.DebugContext.DebugData.RequestURI, "/app/") {
			s := strings.Split(data.DebugContext.DebugData.RequestURI, "/")
			req.SetValue(s[2])
		}
	case "okta.org":
		req.SetValue(oktaPlugin.Organization)
	case "okta.evt.type":
		req.SetValue(data.EventType)
	case "okta.evt.legacytype":
		req.SetValue(data.LegacyEventType)
	case "okta.severity":
		req.SetValue(data.Severity)
	case "okta.message":
		req.SetValue(data.DisplayMessage)
	case "okta.published":
		req.SetValue(data.Published)
	case "okta.actor.id":
		req.SetValue(data.Actor.ID)
	case "okta.actor.Type":
		req.SetValue(data.Actor.Type)
	case "okta.actor.alternateid":
		req.SetValue(data.Actor.AlternateID)
	case "okta.actor.name":
		req.SetValue(data.Actor.DisplayName)
	case "okta.client.zone":
		req.SetValue(data.Client.Zone)
	case "okta.client.ip":
		req.SetValue(data.Client.IPAddress)
	case "okta.client.device":
		req.SetValue(data.Client.Device)
	case "okta.client.id":
		req.SetValue(data.Client.ID)
	case "okta.client.geo.city":
		req.SetValue(data.Client.GeographicalContext.City)
	case "okta.client.geo.state":
		req.SetValue(data.Client.GeographicalContext.State)
	case "okta.client.geo.country":
		req.SetValue(data.Client.GeographicalContext.Country)
	case "okta.client.geo.postalcode":
		req.SetValue(data.Client.GeographicalContext.PostalCode)
	case "okta.client.geo.lat":
		req.SetValue(fmt.Sprintf("%v", data.Client.GeographicalContext.Geolocation.Lat))
	case "okta.client.geo.lon":
		req.SetValue(fmt.Sprintf("%v", data.Client.GeographicalContext.Geolocation.Lon))
	case "okta.useragent.os":
		req.SetValue(data.Client.UserAgent.OS)
	case "okta.useragent.browser":
		req.SetValue(data.Client.UserAgent.Browser)
	case "okta.useragent.raw":
		req.SetValue(data.Client.UserAgent.RawUserAgent)
	case "okta.result":
		req.SetValue(data.Outcome.Result)
	case "okta.reason":
		req.SetValue(data.Outcome.Reason)
	case "okta.transaction.id":
		req.SetValue(data.Transaction.ID)
	case "okta.transaction.type":
		req.SetValue(data.Transaction.Type)
	case "okta.requesturi":
		req.SetValue(data.DebugContext.DebugData.RequestURI)
	case "okta.principal.id":
		req.SetValue(data.DebugContext.DebugData.OriginalPrincipal.ID)
	case "okta.principal.alternateid":
		req.SetValue(data.DebugContext.DebugData.OriginalPrincipal.AlternateID)
	case "okta.principal.type":
		req.SetValue(data.DebugContext.DebugData.OriginalPrincipal.Type)
	case "okta.principal.name":
		req.SetValue(data.DebugContext.DebugData.OriginalPrincipal.DisplayName)
	case "okta.authentication.step":
		req.SetValue(data.AuthenticationContext.AuthenticationStep)
	case "okta.authentication.sessionid":
		req.SetValue(data.AuthenticationContext.ExternalSessionID)
	case "okta.security.asnumber":
		req.SetValue(data.SecurityContext.AsNumber)
	case "okta.security.asorg":
		req.SetValue(data.SecurityContext.AsOrg)
	case "okta.security.isp":
		req.SetValue(data.SecurityContext.ISP)
	case "okta.security.domain":
		req.SetValue(data.SecurityContext.Domain)
	case "okta.target.user.id":
		for _, i := range data.Target {
			if i.Type == "User" {
				req.SetValue(i.ID)
			}
		}
	case "okta.target.user.alternateid":
		for _, i := range data.Target {
			if i.Type == "User" {
				req.SetValue(i.AlternateID)
			}
		}
	case "okta.target.user.name":
		for _, i := range data.Target {
			if i.Type == "User" {
				req.SetValue(i.DisplayName)
			}
		}
	case "okta.target.group.id":
		for _, i := range data.Target {
			if i.Type == "UserGroup" {
				req.SetValue(i.ID)
			}
		}
	case "okta.target.group.alternateid":
		for _, i := range data.Target {
			if i.Type == "UserGroup" {
				req.SetValue(i.AlternateID)
			}
		}
	case "okta.target.group.name":
		for _, i := range data.Target {
			if i.Type == "UserGroup" {
				req.SetValue(i.DisplayName)
			}
		}
	case "okta.mfa.failure.countlast", "okta.mfa.deny.countlast":
		if data.EventType == "user.mfa.okta_verify.deny_push" || (data.EventType == "user.authentication.auth_via_mfa" && data.Outcome.Result == "FAILURE") {
			key := data.EventType + ":" + data.Actor.ID
			shift := req.ArgIndex()
			getvalue, err := oktaPlugin.cache.Get(key)
			if err == nil {
				if getvalue != nil {
					var count uint64
					values := getvalue.([]uint64)
					oldest := evt.Timestamp() - uint64(shift*1e9)
					for _, i := range values {
						if i > uint64(oldest) {
							count++
						}
					}
					req.SetValue(count)
				}
			}
		}
	// case "okta.security.isproxy":
	// 	req.SetValue(data.SecurityContext.IsProxy)
	default:
		return nil
	}

	return nil
}

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (oktaPlugin *Plugin) Open(params string) (source.Instance, error) {
	ctx, cancel := context.WithCancel(context.Background())

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%v.%v", oktaPlugin.Organization, oktaBaseURL), nil)
	if err != nil {
		cancel()
		return nil, err
	}

	since := time.Now().UTC().Add(-60 * time.Second)
	values := req.URL.Query()
	values.Add("since", since.Format(time.RFC3339))
	req.URL.RawQuery = values.Encode()

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "SSWS "+oktaPlugin.APIToken)

	return &PluginInstance{
		client:  &http.Client{},
		request: req,
		cancel:  cancel,
	}, nil
}

// String represents the raw value of on event
// todo: optimize this to cache by event number
func (oktaPlugin *Plugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	return fmt.Sprintf("%v", evtStr), nil
}

// NextBatch is called by Falco plugin framework to get a batch of events from the instance
func (oktaInstance *PluginInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	now := time.Now()
	if now.Before(oktaInstance.lastReqTime.Add(5 * time.Second)) {
		time.Sleep(oktaInstance.lastReqTime.Add(5 * time.Second).Sub(now))
	}

	var logEvents []LogEvent
	values := oktaInstance.request.URL.Query()
	values.Set("limit", fmt.Sprintf("%v", evts.Len()))
	oktaInstance.request.URL.RawQuery = values.Encode()
	oktaInstance.lastReqTime = now

	resp, err := oktaInstance.client.Do(oktaInstance.request)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&logEvents)
	if err != nil {
		return 0, err
	}

	if len(logEvents) == 0 {
		return 0, sdk.ErrTimeout
	}

	i := 0
	for i < evts.Len() && i < len(logEvents) {
		s, _ := json.Marshal(logEvents[i])
		evt := evts.Get(i)
		if _, err := evt.Writer().Write(s); err != nil {
			return i, err
		}
		t, _ := time.Parse(time.RFC3339, logEvents[i].Published)
		evt.SetTimestamp(uint64(t.UnixNano()))
		values.Set("since", t.Add(1*time.Second).Format(time.RFC3339))
		i++
	}
	oktaInstance.request.URL.RawQuery = values.Encode()

	return i, nil
}

func (oktaInstance *PluginInstance) Close() {
	oktaInstance.cancel()
}
