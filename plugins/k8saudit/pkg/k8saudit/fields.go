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

package k8saudit

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

// Fields returns the list of extractor fields exported for K8S Audit events.
func (k *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{
			Type: "string",
			Name: "ka.auditid",
			Desc: "The unique id of the audit event",
		},
		{
			Type: "string",
			Name: "ka.stage",
			Desc: "Stage of the request (e.g. RequestReceived, ResponseComplete, etc.)",
		},
		{
			Type: "string",
			Name: "ka.auth.decision",
			Desc: "The authorization decision",
		},
		{
			Type: "string",
			Name: "ka.auth.reason",
			Desc: "The authorization reason",
		},
		{
			Type: "string",
			Name: "ka.user.name",
			Desc: "The user name performing the request",
		},
		{
			Type:   "string",
			Name:   "ka.user.groups",
			Desc:   "The groups to which the user belongs",
			IsList: true,
		},
		{
			Type: "string",
			Name: "ka.impuser.name",
			Desc: "The impersonated user name",
		},
		{
			Type: "string",
			Name: "ka.verb",
			Desc: "The action being performed",
		},
		{
			Type: "string",
			Name: "ka.uri",
			Desc: "The request URI as sent from client to server",
		},
		{
			Type: "string",
			Name: "ka.uri.param",
			Desc: "The value of a given query parameter in the uri (e.g. when uri=/foo?key=val, ka.uri.param[key] is val).",
			Arg: sdk.FieldEntryArg{
				IsRequired: true,
				IsKey:      true,
			},
		},
		{
			Type: "string",
			Name: "ka.target.name",
			Desc: "The target object name",
		},
		{
			Type: "string",
			Name: "ka.target.namespace",
			Desc: "The target object namespace",
		},
		{
			Type: "string",
			Name: "ka.target.resource",
			Desc: "The target object resource",
		},
		{
			Type: "string",
			Name: "ka.target.subresource",
			Desc: "The target object subresource",
		},
		{
			Type:   "string",
			Name:   "ka.req.binding.subjects",
			Desc:   "When the request object refers to a cluster role binding, the subject (e.g. account/users) being linked by the binding",
			IsList: true,
		},
		{
			Type: "string",
			Name: "ka.req.binding.role",
			Desc: "When the request object refers to a cluster role binding, the role being linked by the binding",
		},
		{
			Type: "string",
			Name: "ka.req.binding.subject.has_name",
			Desc: "Deprecated, always returns \"N/A\". Only provided for backwards compatibility",
			Arg: sdk.FieldEntryArg{
				IsRequired: true,
				IsKey:      true,
			},
		},
		{
			Type: "string",
			Name: "ka.req.configmap.name",
			Desc: "If the request object refers to a configmap, the configmap name",
		},
		{
			Type: "string",
			Name: "ka.req.configmap.obj",
			Desc: "If the request object refers to a configmap, the entire configmap object",
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.image",
			Desc:   "When the request object refers to a pod, the container's images.",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type: "string",
			Name: "ka.req.container.image",
			Desc: "Deprecated by ka.req.pod.containers.image. Returns the image of the first container only",
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.image.repository",
			Desc:   "The same as req.container.image, but only the repository part (e.g. falcosecurity/falco).",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type: "string",
			Name: "ka.req.container.image.repository",
			Desc: "Deprecated by ka.req.pod.containers.image.repository. Returns the repository of the first container only",
		},
		{
			Type: "string",
			Name: "ka.req.pod.host_ipc",
			Desc: "When the request object refers to a pod, the value of the hostIPC flag.",
		},
		{
			Type: "string",
			Name: "ka.req.pod.host_network",
			Desc: "When the request object refers to a pod, the value of the hostNetwork flag.",
		},
		{
			Type: "string",
			Name: "ka.req.container.host_network",
			Desc: "Deprecated alias for ka.req.pod.host_network",
		},
		{
			Type: "string",
			Name: "ka.req.pod.host_pid",
			Desc: "When the request object refers to a pod, the value of the hostPID flag.",
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.host_port",
			Desc:   "When the request object refers to a pod, all container's hostPort values.",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.privileged",
			Desc:   "When the request object refers to a pod, the value of the privileged flag for all containers.",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type: "string",
			Name: "ka.req.container.privileged",
			Desc: "Deprecated by ka.req.pod.containers.privileged. Returns true if any container has privileged=true",
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.allow_privilege_escalation",
			Desc:   "When the request object refers to a pod, the value of the allowPrivilegeEscalation flag for all containers",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.read_only_fs",
			Desc:   "When the request object refers to a pod, the value of the readOnlyRootFilesystem flag for all containers",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type: "string",
			Name: "ka.req.pod.run_as_user",
			Desc: "When the request object refers to a pod, the runAsUser uid specified in the security context for the pod. See ....containers.run_as_user for the runAsUser for individual containers",
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.run_as_user",
			Desc:   "When the request object refers to a pod, the runAsUser uid for all containers",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.eff_run_as_user",
			Desc:   "When the request object refers to a pod, the initial uid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no uid is specified",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type: "string",
			Name: "ka.req.pod.run_as_group",
			Desc: "When the request object refers to a pod, the runAsGroup gid specified in the security context for the pod. See ....containers.run_as_group for the runAsGroup for individual containers",
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.run_as_group",
			Desc:   "When the request object refers to a pod, the runAsGroup gid for all containers",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.eff_run_as_group",
			Desc:   "When the request object refers to a pod, the initial gid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no gid is specified",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.proc_mount",
			Desc:   "When the request object refers to a pod, the procMount types for all containers",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.role.rules",
			Desc:   "When the request object refers to a role/cluster role, the rules associated with the role",
			IsList: true,
		},
		{
			Type:   "string",
			Name:   "ka.req.role.rules.apiGroups",
			Desc:   "When the request object refers to a role/cluster role, the api groups associated with the role's rules",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.role.rules.nonResourceURLs",
			Desc:   "When the request object refers to a role/cluster role, the non resource urls associated with the role's rules",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.role.rules.verbs",
			Desc:   "When the request object refers to a role/cluster role, the verbs associated with the role's rules",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.role.rules.resources",
			Desc:   "When the request object refers to a role/cluster role, the resources associated with the role's rules",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type: "string",
			Name: "ka.req.pod.fs_group",
			Desc: "When the request object refers to a pod, the fsGroup gid specified by the security context.",
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.supplemental_groups",
			Desc:   "When the request object refers to a pod, the supplementalGroup gids specified by the security context.",
			IsList: true,
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.containers.add_capabilities",
			Desc:   "When the request object refers to a pod, all capabilities to add when running the container.",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type: "string",
			Name: "ka.req.service.type",
			Desc: "When the request object refers to a service, the service type",
		},
		{
			Type:   "string",
			Name:   "ka.req.service.ports",
			Desc:   "When the request object refers to a service, the service's ports",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.volumes.hostpath",
			Desc:   "When the request object refers to a pod, all hostPath paths specified for all volumes",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type: "string",
			Name: "ka.req.volume.hostpath",
			Desc: "Deprecated by ka.req.pod.volumes.hostpath. Return true if the provided (host) path prefix is used by any volume",
			Arg: sdk.FieldEntryArg{
				IsRequired: true,
				IsKey:      true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.volumes.flexvolume_driver",
			Desc:   "When the request object refers to a pod, all flexvolume drivers specified for all volumes",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type:   "string",
			Name:   "ka.req.pod.volumes.volume_type",
			Desc:   "When the request object refers to a pod, all volume types for all volumes",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
		{
			Type: "string",
			Name: "ka.resp.name",
			Desc: "The response object name",
		},
		{
			Type: "string",
			Name: "ka.response.code",
			Desc: "The response code",
		},
		{
			Type: "string",
			Name: "ka.response.reason",
			Desc: "The response reason (usually present only for failures)",
		},
		{
			Type: "string",
			Name: "ka.useragent",
			Desc: "The useragent of the client who made the request to the apiserver",
		},
		{
			Type:   "string",
			Name:   "ka.sourceips",
			Desc:   "The IP addresses of the client who made the request to the apiserver",
			IsList: true,
			Arg: sdk.FieldEntryArg{
				IsRequired: false,
				IsIndex:    true,
			},
		},
	}
}
