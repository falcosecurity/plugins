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

#pragma once

#include <condition_variable>
#include <mutex>
#include <string>
#include <grpcpp/grpcpp.h>
#include <falcosecurity/sdk.h>
#include "metadata.grpc.pb.h"

#define MIN_BACKOFF_VALUE 1   // 1 Seconds
#define MAX_BACKOFF_VALUE 120 // 2 Minutes

class K8sMetaClient : public grpc::ClientReadReactor<metadata::Event>
{
    public:
    K8sMetaClient(const std::string& node_name, const std::string& ip_port,
                  const std::string& ca_PEM_encoding, std::mutex& mu,
                  std::condition_variable& cv, std::atomic<bool>& thread_quit,
                  falcosecurity::async_event_handler& handler);
    ~K8sMetaClient() { m_context.TryCancel(); }

    bool Await(uint64_t& backoff_seconds);

    private:
    void OnReadDone(bool ok) override;
    void OnDone(const grpc::Status& s) override;
    void NotifyEnd(grpc::StatusCode c);

    std::unique_ptr<metadata::Metadata::Stub> m_stub;
    grpc::ClientContext m_context;
    metadata::Event m_event;
    falcosecurity::events::asyncevent_e_encoder m_enc;
    grpc::StatusCode m_status_code;

    // Shared with the thread that manages the async capability
    std::mutex& m_mu;
    std::condition_variable& m_cv;
    std::atomic<bool>& m_async_thread_quit;
    falcosecurity::async_event_handler& m_handler;
    // Use to print a log message when we can connect at least one time with the
    // metacollector.
    uint64_t m_correctly_reading;
};
