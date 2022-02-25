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

///////////////////////////////////////////////////////////////////////////////
// This plugin reads Amazon Aurora MySQL and Amazon Aurora PostgreSQL logs
// exported on Cloudwatch.
///////////////////////////////////////////////////////////////////////////////

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/pingcap/parser/ast"
	"io"
	"io/ioutil"
	"math"
	"strconv"
	"strings"
	"time"
)

// Plugin info
const (
	PluginRequiredApiVersion        = "0.3.0"
	PluginID                 uint32 = 999
	PluginName                      = "aurora"
	PluginDescription               = "listens to RDS aurora audit logs via aws Cloudwatch"
	PluginContact                   = "github.com/falcosecurity/plugins/"
	PluginVersion                   = "0.1.0"
	PluginEventSource               = "aws_aurora"
)

const (
	log_group_prefix = "/aws/rds/cluster/"
	log_group_match  = "/audit"
	audit_fields_num = 10
	audit_obj_index  = 8
	polling_freq     = 3
	buffer_size      = 128
)

// Struct for plugin init config
type pluginInitConfig struct {
}

// This is the global plugin state, identifying an instance of this plugin
type pluginContext struct {
	plugins.BasePlugin
	config    pluginInitConfig
	evtNum    uint64
	evtData   auditRecord
	queryData queryFields
}

type auditRecord struct {
	Timestamp    string `json:"timestamp"`
	ServerHost   string `json:"serverhost"`
	Username     string `json:"username"`
	Host         string `json:"host"`
	ConnectionId string `json:"connectionid"`
	QueryId      string `json:"queryid"`
	Operation    string `json:"operation"`
	Database     string `json:"database"`
	Object       string `json:"object"`
	Retcode      string `json:"retcode"`
	Stream       string `json:"stream"`
}

type recordMsg struct {
	Err error
	Rec []byte
}

// This is the open state, identifying an open instance reading Aurora audit logs
type openContext struct {
	source.BaseInstance
	Sess      *session.Session
	CLW       *cloudwatchlogs.CloudWatchLogs
	GroupName *string
	StartTime time.Time
	Records   []*cloudwatchlogs.FilteredLogEvent
	Link      chan *recordMsg
}

func main() {}

func init() {
	p := &pluginContext{}
	extractor.Register(p)
	source.Register(p)
}

func (p *pluginContext) Info() *plugins.Info {
	return &plugins.Info{
		ID:                 PluginID,
		Name:               PluginName,
		Description:        PluginDescription,
		Contact:            PluginContact,
		Version:            PluginVersion,
		RequiredAPIVersion: PluginRequiredApiVersion,
		EventSource:        PluginEventSource,
	}
}

func (p *pluginContext) Init(config string) error {
	p.evtNum = math.MaxUint64
	return nil
}

// Fields exposes to Falco plugin framework all availables fields for this plugin
func (auroraPlugin *pluginContext) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "aurora.timestamp", Desc: "Timestamp with millisec precision."},
		{Type: "string", Name: "aurora.serverhost", Desc: "The name of the instance that the event is logged for."},
		{Type: "string", Name: "aurora.username", Desc: "The connected user name of the user."},
		{Type: "string", Name: "aurora.host", Desc: "The host that the user connected from."},
		{Type: "string", Name: "aurora.connectionid", Desc: "The connection ID number for the logged operation."},
		{Type: "string", Name: "aurora.queryid", Desc: "The query ID number, which can be used for finding the relational table events and related queries. For TABLE events, multiple lines are added."},
		{Type: "string", Name: "aurora.operation", Desc: "The recorded action type. Possible values are: CONNECT, QUERY, READ, WRITE, CREATE, ALTER, RENAME, and DROP."},
		{Type: "string", Name: "aurora.database", Desc: "The active database, as set by the USE command."},
		{Type: "string", Name: "aurora.object", Desc: "For QUERY events, this value indicates the query that the database performed. For TABLE events, it indicates the table name."},
		{Type: "string", Name: "aurora.retcode", Desc: "The return code of the logged operation."},
		{Type: "string", Name: "aurora.stream", Desc: "Cloudwatch stream id used to fetch this log"},
		//Fields from SQL query parsing
		{Type: "string", Name: "aurora.isselect", Desc: "True if a QUERY operation contains SELECT statements."},
		{Type: "string", Name: "aurora.isset", Desc: "True if a QUERY operation contains SET statements."},
		{Type: "string", Name: "aurora.iscreate", Desc: "True if a QUERY operation contains CREATE statements."},
		{Type: "string", Name: "aurora.isdrop", Desc: "True if a QUERY operation contains SELECT statements."},
		{Type: "string", Name: "aurora.isupdate", Desc: "True if a QUERY operation contains UPDATE statements."},
		{Type: "string", Name: "aurora.isinsert", Desc: "True if a QUERY operation contains INSERT statements."},
		{Type: "string", Name: "aurora.isgrant", Desc: "True if a QUERY operation contains GRANT statements."},
		{Type: "string", Name: "aurora.isrevoke", Desc: "True if a QUERY operation contains REVOKE statements."},
		{Type: "string", Name: "aurora.isalter", Desc: "True if a QUERY operation contains ALTER statements."},
		{Type: "string", Name: "aurora.isdelete", Desc: "True if a QUERY operation contains DELETE statements."},
		{Type: "string", Name: "aurora.dropargs", Desc: "DROP statemtent arguments, if present."},
		{Type: "string", Name: "aurora.selectargs", Desc: "SELECT statemtent arguments, if present."},
		{Type: "string", Name: "aurora.setargs", Desc: "SET statemtent arguments, if present."},
		{Type: "string", Name: "aurora.join", Desc: "JOIN statemtent arguments, if present."},
		{Type: "string", Name: "aurora.where", Desc: "WHERE statement arguments, if present."},
		{Type: "string", Name: "aurora.createloc", Desc: "CREATE statemtent location, if present."},
		{Type: "string", Name: "aurora.createargs", Desc: "CREATE statemtent elements, if present."},
		{Type: "string", Name: "aurora.updateargs", Desc: "UPDATE statemtent arguments, if present."},
		{Type: "string", Name: "aurora.insertclmns", Desc: "INSRT statemtent columns argument, if present."},
		{Type: "string", Name: "aurora.inserttable", Desc: "INSERT statemtent table arguments, if present."},
		{Type: "string", Name: "aurora.grantargs", Desc: "GRANT statement roles, if present."},
		{Type: "string", Name: "aurora.grantusr", Desc: "GRANT statement users, if present."},
		{Type: "string", Name: "aurora.revokeusr", Desc: "REVOKE statement user, if present."},
		{Type: "string", Name: "aurora.revokeargs", Desc: "REVOKE statement privileges/roles, if present."},
		{Type: "string", Name: "aurora.altertable", Desc: "ALTER statement table, if present."},
		{Type: "string", Name: "aurora.alterspecs", Desc: "ALTER statement arguments, if present."},
		{Type: "string", Name: "aurora.deletetable", Desc: "DELETE statemtent table arguments, if present."},
	}
}

// String represents the raw value of on event
// (not currently used by Falco plugin framework, only there for future usage)
func (auroraPlugin *pluginContext) String(in io.ReadSeeker) (string, error) {
	rawData, err := ioutil.ReadAll(in)
	res := auditRecord{}
	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}
	err = json.Unmarshal(rawData, &res)
	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}
	return fmt.Sprintf("%s %s %s %s %s %s %s %s %s %s",
		res.Timestamp,
		res.ServerHost,
		res.Username,
		res.Host,
		res.ConnectionId,
		res.QueryId,
		res.Operation,
		res.Database,
		res.Object,
		res.Retcode,
	), nil
}

//Trims only one balanced pair of single quotes, if presents
func trimQuery(s string) string {
	if strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`) && len(s) > 2 {
		return s[1 : len(s)-1]
	}
	return s
}

func (p *pluginContext) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	if p.evtNum != evt.EventNum() {
		rawData, err := ioutil.ReadAll(evt.Reader())
		if err != nil {
			fmt.Println(err.Error())
			return err
		}
		err = json.Unmarshal(rawData, &p.evtData)
		if err != nil {
			fmt.Println(err.Error())
			return err
		}
		//Parse SQL query if necessary
		p.queryData = queryFields{}
		if p.evtData.Operation == "QUERY" {
			var astNode *ast.StmtNode
			query := trimQuery(p.evtData.Object)
			//Cloudwatch logs escapes single quotes with \, which has to be removed
			query = strings.ReplaceAll(query, "\\", "")
			astNode, err = parse(query)
			if err == nil {
				p.queryData = *extract(astNode)
			}
		}
		p.evtNum = evt.EventNum()
	}

	switch req.Field() {
	//Log-related fields
	case "aurora.timestamp":
		req.SetValue(p.evtData.Timestamp)
	case "aurora.serverhost":
		req.SetValue(p.evtData.ServerHost)
	case "aurora.username":
		req.SetValue(p.evtData.Username)
	case "aurora.host":
		req.SetValue(p.evtData.Host)
	case "aurora.connectionid":
		req.SetValue(p.evtData.ConnectionId)
	case "aurora.queryid":
		req.SetValue(p.evtData.QueryId)
	case "aurora.operation":
		req.SetValue(p.evtData.Operation)
	case "aurora.database":
		req.SetValue(p.evtData.Database)
	case "aurora.object":
		req.SetValue(p.evtData.Object)
	case "aurora.retcode":
		req.SetValue(p.evtData.Retcode)
	case "aurora.stream":
		req.SetValue(p.evtData.Stream)

		//Query-related fields. Strconv needed as bool are not supported by the SDK
	case "aurora.isselect":
		req.SetValue(strconv.FormatBool(p.queryData.IsSelect))
	case "aurora.isset":
		req.SetValue(strconv.FormatBool(p.queryData.IsSet))
	case "aurora.iscreate":
		req.SetValue(strconv.FormatBool(p.queryData.IsCreate))
	case "aurora.isdrop":
		req.SetValue(strconv.FormatBool(p.queryData.IsDrop))
	case "aurora.isupdate":
		req.SetValue(strconv.FormatBool(p.queryData.IsUpdate))
	case "aurora.isinsert":
		req.SetValue(strconv.FormatBool(p.queryData.IsInsert))
	case "aurora.isgrant":
		req.SetValue(strconv.FormatBool(p.queryData.IsGrant))
	case "aurora.isrevoke":
		req.SetValue(strconv.FormatBool(p.queryData.IsRevoke))
	case "aurora.isalter":
		req.SetValue(strconv.FormatBool(p.queryData.IsAlter))
	case "aurora.delete":
		req.SetValue(strconv.FormatBool(p.queryData.IsDelete))
	case "aurora.dropargs":
		req.SetValue(strings.Join(p.queryData.DropArgs, " "))
	case "aurora.selectargs":
		req.SetValue(strings.Join(p.queryData.Select, " "))
	case "aurora.setargs":
		req.SetValue(strings.Join(p.queryData.SetArgs, " "))
	case "aurora.join":
		req.SetValue(strings.Join(p.queryData.Join, " "))
	case "aurora.where":
		req.SetValue(strings.Join(p.queryData.Where, " "))
	case "aurora.createloc":
		req.SetValue(strings.Join(p.queryData.CreateLoc, " "))
	case "aurora.createargs":
		req.SetValue(strings.Join(p.queryData.CreateArgs, " "))
	case "aurora.updateargs":
		req.SetValue(strings.Join(p.queryData.UpdateArgs, " "))
	case "aurora.insertclmns":
		req.SetValue(strings.Join(p.queryData.InsertClmns, " "))
	case "aurora.inserttable":
		req.SetValue(strings.Join(p.queryData.InsertTable, " "))
	case "aurora.grantargs":
		req.SetValue(strings.Join(p.queryData.GrantArgs, " "))
	case "aurora.grantusr":
		req.SetValue(strings.Join(p.queryData.GrantUSR, " "))
	case "aurora.revokeusr":
		req.SetValue(strings.Join(p.queryData.RevokeUSR, " "))
	case "aurora.revokeargs":
		req.SetValue(strings.Join(p.queryData.RevokeArgs, " "))
	case "aurora.altertable":
		req.SetValue(strings.Join(p.queryData.AlterTable, " "))
	case "aurora.alterspecs":
		req.SetValue(strings.Join(p.queryData.AlterSpec, " "))
	case "aurora.deletetable":
		req.SetValue(strings.Join(p.queryData.DeleteTable, " "))
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

func (p *pluginContext) Open(params string) (source.Instance, error) {
	oCtx := &openContext{}
	//TODO process also other log categories (error, slowquery...)
	//Eg: /aws/rds/cluster/mycluster/audit
	oCtx.GroupName = aws.String(log_group_prefix + params + log_group_match)
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(cfg.Region)}))
	fmt.Println("Listening ", params, " on region ", cfg.Region)
	oCtx.Sess = sess
	oCtx.CLW = cloudwatchlogs.New(oCtx.Sess)
	//TODO to optionally start listening from the past
	oCtx.StartTime = time.Now()
	oCtx.Link = make(chan *recordMsg, buffer_size)
	go nextEvent(oCtx)
	return oCtx, nil
}

func (o *openContext) NextBatch(bp sdk.PluginState, evts sdk.EventWriters) (int, error) {
	i := 0
	timeout := time.After(30 * time.Millisecond)

	for i < evts.Len() {
		select {
		case msg := <-o.Link:
			if msg.Err != nil {
				return i, msg.Err
			}
			// Add an event to the batch
			evt := evts.Get(i)
			if _, err := evt.Writer().Write(msg.Rec); err != nil {
				return i, err
			}
			i++
		case <-timeout:
			// Timeout occurred, return a partial batch
			return i, sdk.ErrTimeout
		}
	}

	// The batch is full
	return i, nil
}

func nextEvent(oCtx *openContext) {
	var record *auditRecord
	for {
		_, err := oCtx.fetchRecords()
		for i := 0; i < len(oCtx.Records); i++ {
			record, err = parseAudit(*oCtx.Records[i].Message)
			record.Stream = *oCtx.Records[i].LogStreamName
			recordJson, _ := json.Marshal(record)
			oCtx.Link <- &recordMsg{err, recordJson}
		}
		time.Sleep(polling_freq * time.Second)
	}
}

func parseAudit(record string) (*auditRecord, error) {
	split := strings.Split(record, ",")
	if len(split) < audit_fields_num {
		return nil, errors.New("Cannot parse record.")
	}
	// "Object" log field can contain comma-separated SQL statements
	obj := strings.Join(split[audit_obj_index:len(split)-1], ", ")
	return &auditRecord{split[0], split[1], split[2], split[3], split[4], split[5], split[6], split[7], obj, split[9], ""}, nil
}

// Updates the context with all log records newer than StartTime
func (o *openContext) fetchRecords() (int, error) {
	var records []*cloudwatchlogs.FilteredLogEvent
	var filterInput *cloudwatchlogs.FilterLogEventsInput
	filterInput = &cloudwatchlogs.FilterLogEventsInput{LogGroupName: o.GroupName, StartTime: aws.Int64(o.StartTime.UnixMilli())}
	res, err := o.CLW.FilterLogEvents(filterInput)
	if err != nil {
		return 0, err
	}
	if len(res.Events) > 0 {
		//Updates with the most recent timestamp among the records just fetched
		o.StartTime = time.UnixMilli(*res.Events[len(res.Events)-1].Timestamp)
		o.Records = res.Events
	} else {
		o.Records = nil
	}
	return len(records), nil
}
