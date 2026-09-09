/*
Copyright (C) 2026 The Falco Authors.

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

#include <chrono>
#include <deque>
#include <string>
#include <unordered_map>
#include <utility>

// How long a container stays asked before it can be asked again. The
// go-worker retries a missed lookup for about 4s (containerFetchRetryBackoff
// in go-worker/pkg/container/fetcher.go), so by then it has given up on the
// container.
constexpr auto ASKED_CONTAINERS_TTL = std::chrono::seconds(10);

// The containers whose metadata has been asked to the go-worker through
// AskForContainerInfo(). It avoids asking again while a request may still be
// in flight, and lets a container be asked again once the go-worker has
// given up on it, since the container engine may know it by then.
// Entries expire after ttl and are purged lazily, so that every operation is
// O(1): add() purges at most two expired entries, the oldest first, and
// pending() drops only the expired entry it looks up. The size is thus
// bounded by the insertions of the last ttl window plus the expired entries
// that later insertions have not purged yet: a burst lingers, in m_asked and
// m_order, until enough insertions have followed it, and it is never purged
// if none does. erase() removes from m_asked only; m_order keeps the entry
// until the purge reaches it.
class asked_containers
{
    public:
    using clock = std::chrono::steady_clock;

    explicit asked_containers(clock::duration ttl = ASKED_CONTAINERS_TTL):
            m_ttl(ttl)
    {
    }

    // Returns whether the container was asked less than ttl ago. An expired
    // entry is dropped on the way.
    bool pending(const std::string& id, clock::time_point now = clock::now())
    {
        auto it = m_asked.find(id);
        if(it == m_asked.end())
        {
            return false;
        }
        if(now - it->second < m_ttl)
        {
            return true;
        }
        m_asked.erase(it);
        return false;
    }

    // Records that the container has been asked at now, which must not go
    // backwards across calls.
    void add(const std::string& id, clock::time_point now = clock::now())
    {
        // Purge a couple of expired entries per insertion. The order is the
        // insertion order, so the expired entries are at the front.
        for(int i = 0;
            i < 2 && !m_order.empty() && now - m_order.front().first >= m_ttl;
            i++)
        {
            auto it = m_asked.find(m_order.front().second);
            // An entry asked again or erased in the meantime is not ours.
            if(it != m_asked.end() && it->second == m_order.front().first)
            {
                m_asked.erase(it);
            }
            m_order.pop_front();
        }
        m_asked[id] = now;
        m_order.emplace_back(now, id);
    }

    // Forgets the container, e.g. once its metadata arrived or it went away.
    void erase(const std::string& id) { m_asked.erase(id); }

    size_t size() const { return m_asked.size(); }

    private:
    clock::duration m_ttl;
    // When each container was last asked.
    std::unordered_map<std::string, clock::time_point> m_asked;
    // The insertions, hence the expiries, in order.
    std::deque<std::pair<clock::time_point, std::string>> m_order;
};
