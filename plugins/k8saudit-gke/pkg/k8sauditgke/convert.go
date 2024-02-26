// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

package k8sauditgke

import (
	"fmt"
	"strings"

	logging "cloud.google.com/go/logging/apiv2/loggingpb"
	"google.golang.org/genproto/googleapis/cloud/audit"
	"google.golang.org/protobuf/types/known/structpb"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
)

func (p *Plugin) convertLogEntry(logEntry *logging.LogEntry, auditLog *audit.AuditLog) (*auditv1.Event, error) {
	timestampMicro := metav1.NewMicroTime(logEntry.ReceiveTimestamp.AsTime())

	verb := p.getVerb(auditLog.MethodName)
	status := p.getStatus(verb)
	objRef := p.getObjectReference(auditLog.GetResourceName())

	var level auditv1.Level
	var stage auditv1.Stage
	if objRef != nil && (objRef.Subresource == "attach" ||
		objRef.Subresource == "exec") {
		level = "Request"
		stage = "ResponseStarted"
		status.Code = 101
		status.Status = "Switching Protocols (inferred)"
		status.Message = "Switching Protocols (inferred)"
	} else {
		level = "RequestResponse"
		stage = "ResponseComplete"
	}

	annotations := make(map[string]string, len(logEntry.Labels)+len(logEntry.Resource.Labels))
	for l, v := range logEntry.Labels {
		annotations[l] = v
	}
	for l, v := range logEntry.Resource.Labels {
		annotations[l] = v
	}

	requestObj := p.unmarshalResourceObject(auditLog.Request)
	responseObj := p.unmarshalResourceObject(auditLog.Response)

	auditEvent := &auditv1.Event{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Event",
			APIVersion: fmt.Sprintf("%s/v1", auditv1.GroupName),
		},
		Level:      level,
		AuditID:    types.UID(logEntry.InsertId),
		ObjectRef:  objRef,
		Stage:      stage,
		RequestURI: auditLog.ResourceName,
		Verb:       verb,
		User: authv1.UserInfo{
			Username: auditLog.AuthenticationInfo.PrincipalEmail,
		},
		SourceIPs:                []string{auditLog.RequestMetadata.CallerIp},
		UserAgent:                auditLog.RequestMetadata.CallerSuppliedUserAgent,
		ResponseStatus:           status,
		RequestObject:            requestObj,
		ResponseObject:           responseObj,
		RequestReceivedTimestamp: timestampMicro,
		StageTimestamp:           timestampMicro,
		Annotations:              annotations,
	}
	return auditEvent, nil
}

// audit.k8s.io/v1/Event: Object reference this request is targeted at. Does not apply for List-type requests, or non-resource requests.
func (p *Plugin) getObjectReference(resourceName string) *auditv1.ObjectReference {
	if resourceName == "" {
		return nil
	}

	resourceNameParts := strings.Split(string(resourceName), "/")

	var objRef *auditv1.ObjectReference
	if len(resourceNameParts) == 6 &&
		resourceNameParts[2] == "namespaces" {
		// The object reference includes a namespace and object name
		objRef = &auditv1.ObjectReference{
			APIGroup:   resourceNameParts[0],
			APIVersion: resourceNameParts[1],
			Namespace:  resourceNameParts[3],
			Resource:   resourceNameParts[4],
			Name:       resourceNameParts[5],
		}
	} else if len(resourceNameParts) == 5 &&
		resourceNameParts[2] == "namespaces" {
		// The object reference does include a namespace but does not have an
		// object name
		objRef = &auditv1.ObjectReference{
			APIGroup:   resourceNameParts[0],
			APIVersion: resourceNameParts[1],
			Namespace:  resourceNameParts[3],
			Resource:   resourceNameParts[4],
		}
	} else if len(resourceNameParts) == 4 {
		// The object reference does not include a namespace
		objRef = &auditv1.ObjectReference{
			APIGroup:   resourceNameParts[0],
			APIVersion: resourceNameParts[1],
			Resource:   resourceNameParts[2],
			Name:       resourceNameParts[3],
		}
	} else if len(resourceNameParts) >= 7 &&
		resourceNameParts[2] == "namespaces" {
		objRef = &auditv1.ObjectReference{
			APIGroup:    resourceNameParts[0],
			APIVersion:  resourceNameParts[1],
			Namespace:   resourceNameParts[3],
			Resource:    resourceNameParts[4],
			Name:        resourceNameParts[5],
			Subresource: resourceNameParts[6],
		}
	} else if len(resourceNameParts) >= 5 &&
		resourceNameParts[2] != "namespaces" {
		objRef = &auditv1.ObjectReference{
			APIGroup:    resourceNameParts[0],
			APIVersion:  resourceNameParts[1],
			Resource:    resourceNameParts[2],
			Name:        resourceNameParts[3],
			Subresource: resourceNameParts[4],
		}
	} else {
		// Enable for debugging
		// p.logger.Printf("unable to parse resourcename: '%s'", resourceName)
		return nil
	}

	return objRef
}

func (p *Plugin) getVerb(methodName string) string {
	methodNameParts := strings.Split(methodName, ".")
	return methodNameParts[len(methodNameParts)-1]
}

func (p *Plugin) getStatus(verb string) *metav1.Status {
	if verb == "create" {
		return &metav1.Status{
			Status:  "Created (inferred)",
			Code:    201,
			Message: "Created (inferred)",
		}
	}

	return &metav1.Status{
		Status:  "OK (inferred)",
		Code:    200,
		Message: "OK (inferred)",
	}
}

func (p *Plugin) unmarshalResourceObject(obj *structpb.Struct) *runtime.Unknown {
	if obj == nil {
		return nil
	}
	objStruct, err := obj.MarshalJSON()
	if err != nil {
		p.logger.Printf("failed to marshal to json: %v", err)
		return nil
	}
	return &runtime.Unknown{Raw: objStruct}
}
