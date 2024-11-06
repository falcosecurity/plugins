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

#pragma once

#include <falcosecurity/sdk.h>
#include <driver/ppm_events_public.h> // Temporary workaround

namespace plugin_sinsp_filterchecks
{
enum check_type
{
    TYPE_EXE = 0,
    TYPE_PEXE,
    TYPE_AEXE,
    TYPE_EXEPATH,
    TYPE_PEXEPATH,
    TYPE_AEXEPATH,
    TYPE_NAME,
    TYPE_PNAME,
    TYPE_ANAME,
    TYPE_ARGS,
    TYPE_CMDLINE,
    TYPE_PCMDLINE,
    TYPE_ACMDLINE,
    TYPE_CMDNARGS,
    TYPE_CMDLENARGS,
    TYPE_EXELINE,
    TYPE_ENV,
    TYPE_AENV,
    TYPE_CWD,
    TYPE_LOGINSHELLID,
    TYPE_TTY,
    TYPE_PID,
    TYPE_PPID,
    TYPE_APID,
    TYPE_VPID,
    TYPE_PVPID,
    TYPE_SID,
    TYPE_SNAME,
    TYPE_SID_EXE,
    TYPE_SID_EXEPATH,
    TYPE_VPGID,
    TYPE_VPGID_NAME,
    TYPE_VPGID_EXE,
    TYPE_VPGID_EXEPATH,
    TYPE_DURATION,
    TYPE_PPID_DURATION,
    TYPE_PID_CLONE_TS,
    TYPE_PPID_CLONE_TS,
    TYPE_IS_EXE_WRITABLE,
    TYPE_IS_EXE_UPPER_LAYER,
    TYPE_IS_EXE_FROM_MEMFD,
    TYPE_IS_SID_LEADER,
    TYPE_IS_VPGID_LEADER,
    TYPE_EXE_INO,
    TYPE_EXE_INO_CTIME,
    TYPE_EXE_INO_MTIME,
    TYPE_EXE_INO_CTIME_DURATION_CLONE_TS,
    TYPE_EXE_INO_CTIME_DURATION_PIDNS_START,
    TYPE_PIDNS_INIT_START_TS,
    TYPE_CAP_PERMITTED,
    TYPE_CAP_INHERITABLE,
    TYPE_CAP_EFFECTIVE,
    TYPE_IS_CONTAINER_HEALTHCHECK,
    TYPE_IS_CONTAINER_LIVENESS_PROBE,
    TYPE_IS_CONTAINER_READINESS_PROBE,
    TYPE_FDOPENCOUNT,
    TYPE_FDLIMIT,
    TYPE_FDUSAGE,
    TYPE_VMSIZE,
    TYPE_VMRSS,
    TYPE_VMSWAP,
    TYPE_PFMAJOR,
    TYPE_PFMINOR,
    TYPE_TID,
    TYPE_ISMAINTHREAD,
    TYPE_VTID,
    TYPE_NAMETID,
    TYPE_EXECTIME,
    TYPE_TOTEXECTIME,
    TYPE_CGROUPS,
    TYPE_CGROUP,
    TYPE_NTHREADS,
    TYPE_NCHILDS,
    TYPE_THREAD_CPU,
    TYPE_THREAD_CPU_USER,
    TYPE_THREAD_CPU_SYSTEM,
    TYPE_THREAD_VMSIZE,
    TYPE_THREAD_VMRSS,
    TYPE_THREAD_VMSIZE_B,
    TYPE_THREAD_VMRSS_B,
    TYPE_CONTAINER_ID,
    TYPE_CONTAINER_FULL_CONTAINER_ID,
    TYPE_CONTAINER_NAME,
    TYPE_CONTAINER_IMAGE,
    TYPE_CONTAINER_IMAGE_ID,
    TYPE_CONTAINER_TYPE,
    TYPE_CONTAINER_PRIVILEGED,
    TYPE_CONTAINER_MOUNTS,
    TYPE_CONTAINER_MOUNT,
    TYPE_CONTAINER_MOUNT_SOURCE,
    TYPE_CONTAINER_MOUNT_DEST,
    TYPE_CONTAINER_MOUNT_MODE,
    TYPE_CONTAINER_MOUNT_RDWR,
    TYPE_CONTAINER_MOUNT_PROPAGATION,
    TYPE_CONTAINER_IMAGE_REPOSITORY,
    TYPE_CONTAINER_IMAGE_TAG,
    TYPE_CONTAINER_IMAGE_DIGEST,
    TYPE_CONTAINER_HEALTHCHECK,
    TYPE_CONTAINER_LIVENESS_PROBE,
    TYPE_CONTAINER_READINESS_PROBE,
    TYPE_CONTAINER_START_TS,
    TYPE_CONTAINER_DURATION,
    TYPE_CONTAINER_IP_ADDR,
    TYPE_CONTAINER_CNIRESULT,
    TYPE_FDNUM,
    TYPE_FDTYPE,
    TYPE_FDTYPECHAR,
    TYPE_FDNAME,
    TYPE_DIRECTORY,
    TYPE_FILENAME,
    TYPE_IP,
    TYPE_CLIENTIP,
    TYPE_SERVERIP,
    TYPE_LIP,
    TYPE_RIP,
    TYPE_PORT,
    TYPE_CLIENTPORT,
    TYPE_SERVERPORT,
    TYPE_LPORT,
    TYPE_RPORT,
    TYPE_L4PROTO,
    TYPE_SOCKFAMILY,
    TYPE_IS_SERVER,
    TYPE_UID,
    TYPE_CONTAINERNAME,
    TYPE_CONTAINERDIRECTORY,
    TYPE_PROTO,
    TYPE_CLIENTPROTO,
    TYPE_SERVERPROTO,
    TYPE_LPROTO,
    TYPE_RPROTO,
    TYPE_NET,
    TYPE_CNET,
    TYPE_SNET,
    TYPE_LNET,
    TYPE_RNET,
    TYPE_IS_CONNECTED,
    TYPE_NAME_CHANGED,
    TYPE_CLIENTIP_NAME,
    TYPE_SERVERIP_NAME,
    TYPE_LIP_NAME,
    TYPE_RIP_NAME,
    TYPE_DEV,
    TYPE_DEV_MAJOR,
    TYPE_DEV_MINOR,
    TYPE_INO,
    TYPE_FDNAMERAW,
    TYPE_FDTYPES,
    TYPE_FSPATH_NAME,
    TYPE_FSPATH_NAMERAW,
    TYPE_FSPATH_SOURCE,
    TYPE_FSPATH_SOURCERAW,
    TYPE_FSPATH_TARGET,
    TYPE_FSPATH_TARGETRAW,
    TYPE_CUSTOM_ANAME_LINEAGE_CONCAT,
    TYPE_CUSTOM_AEXE_LINEAGE_CONCAT,
    TYPE_CUSTOM_AEXEPATH_LINEAGE_CONCAT,
    TYPE_CUSTOM_FDNAME_PART1,
    TYPE_CUSTOM_FDNAME_PART2,
};
}

// Below copied from falcosecurity/libs userspace/libsinsp/event.h
///////////////////////////////////////////////////////////////////////////////
// Event arguments
///////////////////////////////////////////////////////////////////////////////
enum filtercheck_field_flags
{
	EPF_NONE              = 0,
	EPF_FILTER_ONLY       = 1 << 0, ///< this field can only be used as a filter.
	EPF_PRINT_ONLY        = 1 << 1, ///< this field can only be printed.
	EPF_ARG_REQUIRED      = 1 << 2, ///< this field includes an argument, under the form 'property.argument'.
	EPF_TABLE_ONLY        = 1 << 3, ///< this field is designed to be used in a table and won't appear in the field listing.
	EPF_INFO              = 1 << 4, ///< this field contains summary information about the event.
	EPF_CONVERSATION      = 1 << 5, ///< this field can be used to identify conversations.
	EPF_IS_LIST           = 1 << 6, ///< this field is a list of values.
	EPF_ARG_ALLOWED       = 1 << 7, ///< this field optionally includes an argument.
	EPF_ARG_INDEX         = 1 << 8, ///< this field accepts numeric arguments.
	EPF_ARG_KEY           = 1 << 9, ///< this field accepts string arguments.
	EPF_DEPRECATED        = 1 << 10,///< this field is deprecated.
	EPF_NO_TRANSFORMER    = 1 << 11,///< this field cannot have a field transformer.
	EPF_NO_RHS            = 1 << 12,///< this field cannot have a right-hand side filter check, and cannot be used as a right-hand side filter check.
    // Custom below
    EPF_ANOMALY_PLUGIN    = 1 << 13,///< this field is supported by the anomalydetection plugin
};

// Below copied from falcosecurity/libs userspace/libsinsp/sinsp_filtercheck.h
/*!
  \brief Information about a filter/formatting field.
*/
struct filtercheck_field_info
{
	ppm_param_type m_type = PT_NONE; ///< Field type.
	uint32_t m_flags = 0;  ///< Field flags.
	ppm_print_format m_print_format = PF_NA;  ///< If this is a numeric field, this flag specifies if it should be rendered as octal, decimal or hex.
	char m_name[64];  ///< Field name.
	char m_display[64];  ///< Field display name (short description). May be empty.
	char m_description[1024];  ///< Field description.

	//
	// Return true if this field must have an argument
	//
	inline bool is_arg_required() const
	{
		return m_flags & EPF_ARG_REQUIRED;
	}

	//
	// Return true if this field can optionally have an argument
	//
	inline bool is_arg_allowed() const
	{
		return m_flags & EPF_ARG_REQUIRED;
	}

	//
	// Returns true if this field can have an argument, either
	// optionally or mandatorily
	//
	inline bool is_arg_supported() const
	{
		return (m_flags & EPF_ARG_REQUIRED) ||(m_flags & EPF_ARG_ALLOWED);
	}

	//
	// Returns true if this field is a list of values
	//
	inline bool is_list() const
	{
		return m_flags & EPF_IS_LIST;
	}

	//
	// Returns true if this filter check can support a rhs filter check instead of a const value.
	//
	inline bool is_rhs_field_supported() const
	{
		return !(m_flags & EPF_NO_RHS);
	}

	//
	// Returns true if this filter check can support an extraction transformer on it.
	//
	inline bool is_transformer_supported() const
	{
		return !(m_flags & EPF_NO_TRANSFORMER);
	}
};
