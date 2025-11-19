#pragma once

#include <list>
#include <unordered_map>
#include <utility>

template<typename Key, typename Value> class LRU
{
    public:
    LRU(size_t cap = 100): m_cap(cap) {}

    void set(const Key& k, const Value& v)
    {
        auto it = m_key_to_value.find(k);
        if(it == m_key_to_value.end())
        {
            // Didn't find the element in the cache:
            // move the element on top of the list.
            m_values.emplace_front(k);
            // If we reached max capacity pop the last element.
            if(m_values.size() > m_cap)
            {
                m_key_to_value.erase(m_values.back());
                m_values.pop_back();
            }
            // Populate the cache.
            m_key_to_value.insert({k, {v, m_values.begin()}});
        }
        else
        {
            // Update the element pointers moving it on the front of the list
            m_values.splice(m_values.begin(), m_values, it->second.second);
            // The element could be different: update it anyway.
            it->second.first = v;
            // Update the iterator accordingly
            it->second.second = m_values.begin();
        }
    }

    bool get(const Key& k, Value& v)
    {
        auto it = m_key_to_value.find(k);
        if(it != m_key_to_value.end())
        {
            // We have the value in the cache
            v = it->second.first;
            // Update the element pointers moving it on the front of the list
            m_values.splice(m_values.begin(), m_values, it->second.second);
            // Update the iterator accordingly
            it->second.second = m_values.begin();
            return true;
        }
        return false;
    }

    private:
    size_t m_cap = 100;
    std::unordered_map<Key, std::pair<Value, typename std::list<Key>::iterator>>
            m_key_to_value;
    std::list<Key> m_values;
};
