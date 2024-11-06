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

#include "num/cms.h"
#include "plugin_mutex.h"

#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <memory>

class ThreadManager {
public:
    ThreadManager() : m_stop_requested(false) {}

    ~ThreadManager()
    {
        stop_threads();
    }

    void stop_threads()
    {
        {
            std::lock_guard<std::mutex> lock(m_thread_mutex);
            m_stop_requested = true;
        }

        {
            std::lock_guard<std::mutex> lock(m_thread_mutex);
            for (auto& t : m_threads)
            {
                if (t.joinable())
                {
                    t.join();
                }
            }
            m_threads.clear();
        }
    }

    template<typename T>
    void start_periodic_count_min_sketch_reset_worker(int id, uint64_t interval_ms, plugin_anomalydetection::Mutex<std::vector<std::shared_ptr<plugin::anomalydetection::num::cms<T>>>>& count_min_sketches)
    {
        if (interval_ms > 100)
        {
            auto worker = [id, interval_ms, &count_min_sketches, this]() {
                periodic_count_min_sketch_reset_worker<T>(id, interval_ms, count_min_sketches);
            };

            std::thread worker_thread(worker);
            {
                std::lock_guard<std::mutex> lock(m_thread_mutex);
                m_threads.push_back(std::move(worker_thread));
            }
        }
    }
    std::atomic<bool> m_stop_requested;

private:
    std::vector<std::thread> m_threads;
    std::mutex m_thread_mutex;

    template<typename T>
    void reset_sketches_worker(int id, plugin_anomalydetection::Mutex<std::vector<std::shared_ptr<plugin::anomalydetection::num::cms<T>>>>& count_min_sketches)
    {
        auto sketches = count_min_sketches.lock();
        if (id >= 0 && id < sketches->size())
        {
            auto& sketch_ptr = sketches->at(id);
            if (sketch_ptr)
            {
                sketch_ptr->reset();
            }
        }
    }

    template<typename T>
    void periodic_count_min_sketch_reset_worker(int id, uint64_t interval_ms, plugin_anomalydetection::Mutex<std::vector<std::shared_ptr<plugin::anomalydetection::num::cms<T>>>>& count_min_sketches)
    {
        std::chrono::milliseconds interval(interval_ms);
        while (true)
        {
            std::this_thread::sleep_for(interval);
            {
                std::lock_guard<std::mutex> lock(m_thread_mutex);
                if (m_stop_requested)
                    break;
            }

            try
            {
                reset_sketches_worker<T>(id, count_min_sketches);
            } catch (const std::exception& e)
            {
            }
        }
    }
};
