/*
Copyright (C) 2023 The Falco Authors.

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

#include "grpc_client.h"
#include "shared_with_tests_consts.h"

#include <iostream>
#include <memory>
#include <string>
#include <google/protobuf/util/json_util.h>
#include <spdlog/spdlog.h>

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::Status;
using metadata::Event;
using metadata::Selector;

K8sMetaClient::K8sMetaClient(const std::string& node_name,
                             const std::string& ip_port,
                             const std::string& ca_PEM_encoding, std::mutex& mu,
                             std::condition_variable& cv,
                             std::atomic<bool>& thread_quit,
                             falcosecurity::async_event_handler& handler):
        m_status_code(grpc::StatusCode::DO_NOT_USE),
        m_cv(cv), m_mu(mu), m_async_thread_quit(thread_quit),
        m_handler(handler), m_correctly_reading(0)
{
    metadata::Selector sel;
    sel.set_nodename(node_name);
    sel.clear_resourcekinds();

    /// todo! one day we could expose them to the user.
    (*sel.mutable_resourcekinds())["Pod"] = "true";
    (*sel.mutable_resourcekinds())["Namespace"] = "true";
    (*sel.mutable_resourcekinds())["Deployment"] = "true";
    (*sel.mutable_resourcekinds())["Service"] = "true";
    (*sel.mutable_resourcekinds())["ReplicaSet"] = "true";
    (*sel.mutable_resourcekinds())["ReplicaController"] = "true";

    if(!ca_PEM_encoding.empty())
    {
        m_stub = metadata::Metadata::NewStub(grpc::CreateChannel(
                ip_port, grpc::SslCredentials(grpc::SslCredentialsOptions(
                                 {ca_PEM_encoding, "", ""}))));
    }
    else
    {
        // We use an insecure channel
        m_stub = metadata::Metadata::NewStub(grpc::CreateChannel(
                ip_port, grpc::InsecureChannelCredentials()));
    }

    m_stub->async()->Watch(&m_context, &sel, this);
    StartRead(&m_event);
    StartCall();
}

void K8sMetaClient::NotifyEnd(grpc::StatusCode c)
{
    std::unique_lock<std::mutex> l(m_mu);
    m_status_code = c;
    m_cv.notify_one();
}

void K8sMetaClient::OnReadDone(bool ok)
{
    if(!ok)
    {
        // In case of failure we will call `OnDone` method
        return;
    }

    // Copy the JSON event into the string.
    std::string json_string;
    google::protobuf::util::JsonPrintOptions options;
    auto status = MessageToJsonString(m_event, &json_string, options);
    if(!status.ok())
    {
        SPDLOG_ERROR("cannot convert message to json: {}", status.ToString());
        NotifyEnd(grpc::StatusCode::DATA_LOSS);
        return;
    }

    if(m_correctly_reading == 0)
    {
        // Print a log just once
        m_correctly_reading++;
        SPDLOG_INFO("The plugin received at least one event from the "
                    "k8s-metacollector");
    }

    m_enc.set_name(ASYNC_EVENT_NAME);
    m_enc.set_data((void*)json_string.c_str(), json_string.size() + 1);
    m_enc.encode(m_handler.writer());
    m_handler.push();
    StartRead(&m_event);
}
// Some errors reported by Falco in failure conditions:
// 1. When the server exposes a TLS certificate but the client doesn't:
// ```
// [2023-11-29 16:42:05.598] [error] [k8smeta] "error during the RPC call. Error
// code (UNAVAILABLE), error message (failed to connect to all addresses; last
// error: UNAVAILABLE: ipv4:127.0.0.1:45000: Socket closed)"
// ```
//
// 2. When the client exposes a TLS certificate but the server doesn't:
// ```
// E1129 16:45:02.792586417   17566 ssl_transport_security.cc:1432] Handshake
// failed with fatal error SSL_ERROR_SSL: error:100000f7:SSL
// routines:OPENSSL_internal:WRONG_VERSION_NUMBER. E1129 16:45:02.793554245
// 17580 ssl_transport_security.cc:1432]       Handshake failed with fatal error
// SSL_ERROR_SSL: error:100000f7:SSL
// routines:OPENSSL_internal:WRONG_VERSION_NUMBER. [2023-11-29 16:45:02.793]
// [error] [k8smeta] error during the RPC call. Error code (14), error message
// (failed to connect to all addresses; last error: UNKNOWN:
// ipv4:127.0.0.1:45000: Ssl handshake failed: SSL_ERROR_SSL: error:100000f7:SSL
// routines:OPENSSL_internal:WRONG_VERSION_NUMBER)
// ```
//
// 3. If the port or the node name in the plugin init params are wrong
// ```
// [2023-11-29 17:01:08.802] [error] [k8smeta] error during the RPC call. Error
// code (14), error message (failed to connect to all addresses; last error:
// UNKNOWN: ipv4:127.0.0.1:45001: Failed to connect to remote host: Connection
// refused)
// ```
//
// 4. If the CA root PEM is wrong
// ```
// [2023-11-29 17:04:17.633] [error] [k8smeta] Cannot open any PEM bundle at
// '/etc/invalid'. Proceed with insecure connection
// ```
//
// 5. If the k8s-metacollector restart
// ```
// [2023-11-29 17:07:11.692] [error] [k8smeta] error during the RPC call. Error
// code (14), error message (Socket closed) [2023-11-29 17:07:13.707] [error]
// [k8smeta] error during the RPC call. Error code (14), error message (failed
// to connect to all addresses; last error: UNKNOWN: ipv4:127.0.0.1:45000:
// Failed to connect to remote host: Connection refused)
// ```
//
void K8sMetaClient::OnDone(const grpc::Status& s)
{
    switch(s.error_code())
    {
    case grpc::StatusCode::OK:
        SPDLOG_INFO("gRPC call correctly terminated.");
        break;

    case grpc::StatusCode::CANCELLED:
        // This happens during Falco hot reload or on termination
        SPDLOG_INFO("gRPC call cancelled. Full message: ({})",
                    s.error_message());
        break;

    default:
        SPDLOG_ERROR("error during the RPC call. Error code ({}), error "
                     "message ({})",
                     int32_t(s.error_code()), s.error_message());
        break;
    }
    NotifyEnd(s.error_code());
}

// Return true if we need to restart the connection, false if we have done.
bool K8sMetaClient::Await(uint64_t& backoff_seconds)
{
    std::unique_lock<std::mutex> l(m_mu);
    // m_status_code != grpc::StatusCode::DO_NOT_USE means that we have a new
    // status and we need to terminate
    m_cv.wait(l,
              [this]
              {
                  return m_async_thread_quit.load() ||
                         m_status_code != grpc::StatusCode::DO_NOT_USE;
              });

    if(m_async_thread_quit.load())
    {
        // We don't a restart if we receive the stop.
        return false;
    }

    switch(m_status_code)
    {
    case grpc::StatusCode::OK:
        return false;

    case grpc::StatusCode::UNAUTHENTICATED:
    case grpc::StatusCode::PERMISSION_DENIED:
    case grpc::StatusCode::FAILED_PRECONDITION:
    case grpc::StatusCode::UNAVAILABLE:
        // In these cases, we want to update the backoff
        backoff_seconds = backoff_seconds * 2 >= MAX_BACKOFF_VALUE
                                  ? MAX_BACKOFF_VALUE
                                  : backoff_seconds * 2;
        return true;

    default:
        // Reset the backoff
        backoff_seconds = MIN_BACKOFF_VALUE;
        break;
    }
    // The only case in which we don't restart is when the server correctly
    // terminates the gRPC call.
    return true;
}
