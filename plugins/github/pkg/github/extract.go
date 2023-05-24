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

package github

import (
	"fmt"
	"io/ioutil"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
)

// Return the fields supported for extraction.
func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "github.type", Display: "Message Type", Desc: "Message type, e.g. 'star' or 'repository'."},
		{Type: "string", Name: "github.action", Display: "Action Type", Desc: "The github event action. This field typically qualifies the github.type field. For example, a message of type 'star' can have action 'created' or 'deleted'."},
		{Type: "string", Name: "github.user", Display: "User", Desc: "Name of the user that triggered the event."},
		{Type: "string", Name: "github.repo", Display: "Repository", Desc: "Name of the git repository where the event occurred. Github Webhook payloads contain the repository property when the event occurs from activity in a repository."},
		{Type: "string", Name: "github.org", Display: "Organization", Desc: "Name of the organization the git repository belongs to."},
		{Type: "string", Name: "github.owner", Display: "Owner", Desc: "Name of the repository's owner."},
		{Type: "string", Name: "github.repo.public", Display: "Public", Desc: "'true' if the repository affected by the action is public. 'false' otherwise."},
		{Type: "string", Name: "github.collaborator.name", Display: "Collaborator Name", Desc: "The member name for message that add or remove users."},
		{Type: "string", Name: "github.collaborator.role", Display: "Collaborator Role", Desc: "The member name for message that add or remove users."},
		{Type: "string", Name: "github.webhook.id", Display: "Webhook ID", Desc: "When a new webhook has been created, the webhook id."},
		{Type: "string", Name: "github.webhook.type", Display: "Webhook Type", Desc: "When a new webhook has been created, the webhook type, e.g. 'repository'."},
		{Type: "string", Name: "github.commit.modified", Display: "Modified Files", Desc: "Comma separated list of files that have been modified."},
		{Type: "string", Name: "github.diff.has_secrets", Display: "Contains Secrets", Desc: "For push messages, 'true' if the diff of one of the commits contains a secret."},
		{Type: "string", Name: "github.diff.committed_secrets.desc", Display: "Secret Descriptions", Desc: "For push messages, if one of the commits includes one or more secrets (AWS keys, github tokens...), this field contains the description of each of the committed secrets, as a comma separated list."},
		{Type: "string", Name: "github.diff.committed_secrets.files", Display: "Secret Files", Desc: "For push messages, if one of the commits includes one or more secrets (AWS keys, github tokens...), this field contains the names of the files in which each of the secrets was committed, as a comma separated list."},
		{Type: "string", Name: "github.diff.committed_secrets.lines", Display: "Secret Lines", Desc: "For push messages, if one of the commits includes one or more secrets (AWS keys, github tokens...), this field contains the file line positions of the committed secrets, as a comma separated list."},
		{Type: "string", Name: "github.diff.committed_secrets.links", Display: "Secret Links", Desc: "For push messages, if one of the commits includes one or more secrets (AWS keys, github tokens...), this field contains the github source code link for each of the committed secrets, as a comma separated list."},
		{Type: "string", Name: "github.workflow.has_miners", Display: "Workflow Has Miner", Desc: "For workflow_run messages, 'true' if the a miner has been detected in the workflow definition file."},
		{Type: "string", Name: "github.workflow.miners.type", Display: "Workflow Miner Type", Desc: "For workflow_run messages, if one or more miners is detected in the workflow definition file, this field contains the type of each of the detected miner, as a comma separated list (e.g. xmrig, stratum)."},
		{Type: "string", Name: "github.workflow.filename", Display: "Workflow File", Desc: "For workflow_run messages, the name of the workflow definition file."},
	}
}

func getMatchField(jdata *fastjson.Value, matchField string, fType string) (bool, string) {
	res := ""

	flist := jdata.GetArray("files")
	if flist == nil {
		return false, ""
	}

	for _, file := range flist {
		mlist := file.GetArray("matches")
		for _, cinfo := range mlist {
			if fType == "string" {
				res += string(cinfo.Get(matchField).GetStringBytes())
			} else if fType == "uint64" {
				res += fmt.Sprintf("%v", cinfo.GetUint64(matchField))
			} else if fType == "file" {
				res += string(file.Get("name").GetStringBytes())
			}

			res += ","
		}
		if res[len(res)-1] == ',' {
			res = res[0 : len(res)-1]
		}
	}

	return true, res
}

func getMinerTypes(jdata *fastjson.Value) (bool, string) {
	res := ""

	mlist := jdata.GetArray("workflow_miner_detections", "matches")
	if mlist == nil {
		return false, ""
	}

	tlist := map[string]bool{}

	for _, cinfo := range mlist {
		tlist[string(cinfo.Get("type").GetStringBytes())] = true
	}
	for t, _ := range tlist {
		res += fmt.Sprintf("%s", t)
		res += ","
	}
	if res[len(res)-1] == ',' {
		res = res[0 : len(res)-1]
	}

	return true, res
}

func getfieldStr(jdata *fastjson.Value, field string) (bool, string) {
	var res string

	switch field {
	case "github.type":
		res = string(jdata.GetStringBytes("webhook_type"))
	case "github.action":
		res = string(jdata.GetStringBytes("action"))
	case "github.user":
		res = string(jdata.Get("sender", "login").GetStringBytes())
	case "github.repo":
		res = string(jdata.Get("repository", "html_url").GetStringBytes())
	case "github.org":
		res = string(jdata.Get("organization", "login").GetStringBytes())
	case "github.owner":
		res = string(jdata.Get("repository", "owner", "login").GetStringBytes())
	case "github.repo.public":
		isPrivate := jdata.Get("repository", "private").GetBool()
		if isPrivate {
			res = "false"
		} else {
			res = "true"
		}
	case "github.collaborator.name":
		res = string(jdata.Get("member", "login").GetStringBytes())
	case "github.collaborator.role":
		res = string(jdata.Get("changes", "permission", "to").GetStringBytes())
	case "github.webhook.id":
		res = fmt.Sprintf("%v", jdata.GetUint64("hook", "id"))
	case "github.webhook.type":
		res = string(jdata.Get("hook", "type").GetStringBytes())
	case "github.commit.modified":
		clist := jdata.GetArray("commits")
		if clist == nil {
			break
		}
		for _, commit := range clist {
			mlist := commit.GetArray("modified")
			for _, fname := range mlist {
				res += string(fname.GetStringBytes())
				res += ","
			}
			if res[len(res)-1] == ',' {
				res = res[0 : len(res)-1]
			}
		}
	case "github.diff.has_secrets":
		flist := jdata.GetArray("files")
		if flist == nil {
			break
		}

		res = "false"

		for _, file := range flist {
			mlist := file.GetArray("matches")
			if len(mlist) > 0 {
				res = "true"
				break
			}
		}
	case "github.diff.committed_secrets.desc":
		return getMatchField(jdata, "desc", "string")
	case "github.diff.committed_secrets.files":
		return getMatchField(jdata, "", "file")
	case "github.diff.committed_secrets.lines":
		return getMatchField(jdata, "line", "uint64")
	case "github.diff.committed_secrets.links":
		repo := string(jdata.Get("repository", "html_url").GetStringBytes())
		flist := jdata.GetArray("files")
		if flist == nil {
			break
		}

		for _, file := range flist {
			mlist := file.GetArray("matches")
			for _, cinfo := range mlist {
				res += fmt.Sprintf("%v/blob/%v/%v/#L%v",
					repo,
					string(jdata.Get("head_commit", "id").GetStringBytes()),
					string(file.Get("name").GetStringBytes()),
					cinfo.GetUint64("line"))
				res += ","
			}
			if res[len(res)-1] == ',' {
				res = res[0 : len(res)-1]
			}
		}
	case "github.workflow.has_miners":
		wi := jdata.GetArray("workflow_miner_detections", "matches")
		if wi == nil {
			return false, ""
		}

		if len(wi) == 0 {
			res = "false"
		} else {
			res = "true"
		}
	case "github.workflow.miners.type":
		return getMinerTypes(jdata)
	case "github.workflow.filename":
		res = string(jdata.Get("workflow", "path").GetStringBytes())
	default:
		return false, ""
	}

	return true, res
}

// Extract a field value from an event.
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	// Decode the json, but only if we haven't done it yet for this event
	if evt.EventNum() != p.jdataEvtnum {
		// Read the event data
		data, err := ioutil.ReadAll(evt.Reader())
		if err != nil {
			return err
		}

		// For this plugin, events are always strings
		evtStr := string(data)

		p.jdata, err = p.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present.
			return err
		}
		p.jdataEvtnum = evt.EventNum()
	}

	// Extract the field value
	present, value := getfieldStr(p.jdata, req.Field())
	if present {
		req.SetValue(value)
	}

	return nil
}
