// SPDX-License-Identifier: Apache-2.0
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

#include <falcosecurity/sdk.h>

#define PLUGIN_ID 4
#define PLUGIN_NAME "dummy_c"
#define PLUGIN_DESCRIPTION "Reference plugin for educational purposes"
#define PLUGIN_CONTACT "github.com/falcosecurity/plugins"
#define PLUGIN_VERSION "0.2.3"
#define PLUGIN_SOURCE_NAME "dummy_c"

#define PLUGIN_LOG_PREFIX "[dummy_c]"
#define DEFAULT_JITTER 10
#define DEFAULT_MAX_EVENTS 20
#define DEFAULT_START_VALUE 1

class dummy_source
{
    public:
    virtual ~dummy_source() = default;

    dummy_source(uint64_t max_evts, uint64_t start, uint64_t jitter):
            m_event_count(0), m_max_evts(max_evts), m_sample_value(start),
            m_jitter(jitter), m_enc()
    {
    }

    falcosecurity::result_code next_event(falcosecurity::event_writer &evt)
    {
        if(m_event_count >= m_max_evts)
        {
            return falcosecurity::result_code::SS_PLUGIN_EOF;
        }
        m_event_count++;

        // Increment sample by 1, also add a jitter of [0:jitter]
        m_sample_value += 1 + (random() % (m_jitter + 1));

        // we will memcpy the content of `m_sample_value` inside `m_enc.encode`.
        m_enc.set_data((void *)&m_sample_value, sizeof(uint64_t));
        m_enc.encode(evt);
        return falcosecurity::result_code::SS_PLUGIN_SUCCESS;
    }

    private:
    uint64_t m_event_count;
    uint64_t m_max_evts;
    uint64_t m_sample_value;
    uint64_t m_jitter;
    falcosecurity::events::pluginevent_e_encoder m_enc;
};

class dummy
{
    public:
    virtual ~dummy() = default;

    std::string get_name() { return PLUGIN_NAME; }

    std::string get_version() { return PLUGIN_VERSION; }

    std::string get_description() { return PLUGIN_DESCRIPTION; }

    std::string get_contact() { return PLUGIN_CONTACT; }

    uint32_t get_id() { return PLUGIN_ID; };

    std::string get_event_source() { return PLUGIN_SOURCE_NAME; }

    std::string get_last_error() { return m_lasterr; }

    bool init(falcosecurity::init_input &in)
    {
        // Config is optional. In this case, defaults are used.
        if(in.get_config().empty())
        {
            return true;
        }

        try
        {
            auto cfg = nlohmann::json::parse(in.get_config());
            auto it = cfg.find("jitter");
            if(it != cfg.end())
            {
                m_jitter = *it;
            }
        }
        catch(std::exception e)
        {
            m_lasterr = "unable to parse the json config";
            log_error(m_lasterr);
            return false;
        }

        return true;
    }

    std::vector<std::string> get_extract_event_sources()
    {
        return {PLUGIN_SOURCE_NAME};
    }

    std::vector<falcosecurity::field_info> get_fields()
    {
        // We need to compile at least with c++11 to use an ordinary initializer
        // list.
        auto divisibile_arg = falcosecurity::field_arg();
        divisibile_arg.required = true;
        divisibile_arg.index = true;

        using ft = falcosecurity::field_value_type;
        return {
                {ft::FTYPE_UINT64, "dummy.divisible",
                 "Return 1 if the value is divisible by the provided divisor, "
                 "0 otherwise",
                 "Return 1 if the value is divisible by the provided divisor, "
                 "0 otherwise",
                 divisibile_arg},
                {ft::FTYPE_UINT64, "dummy.value",
                 "The sample value in the event",
                 "The sample value in the event"},
                {ft::FTYPE_STRING, "dummy.strvalue",
                 "The sample value in the event, as a string",
                 "The sample value in the event, as a string"},
        };
    }

    void log_error(std::string err_mess)
    {
        printf("%s %s\n", PLUGIN_LOG_PREFIX, err_mess.c_str());
    }

    bool extract(const falcosecurity::extract_fields_input &in)
    {
        auto &req = in.get_extract_request();
        falcosecurity::events::pluginevent_e_decoder dec(in.get_event_reader());
        uint32_t len = 0;
        auto sample = *((uint64_t *)(dec.get_data(len)));
        if(len != sizeof(uint64_t))
        {
            log_error("invalid event payload");
        }

        switch(req.get_field_id())
        {
        case 0: // dummy.divisible
        {
            if(!req.is_arg_present())
            {
                log_error("'dummy.divisible' requires an argument but no "
                          "argument is provided");
                return false;
            }

            uint64_t res = 0;
            auto divisor = req.get_arg_index();
            if((sample % divisor) == 0)
            {
                res = 1;
            }
            req.set_value(res, true);
            return true;
        }
        case 1: // dummy.value
        {
            req.set_value(sample, true);
            return true;
        }
        case 2: // dummy.strvalue
        {
            // The event payload is simply the sample, as a string
            req.set_value(std::to_string(sample), true);
            return true;
        }
        default:
            m_lasterr = "no known field: " + std::to_string(req.get_field_id());
            log_error(m_lasterr);
            return false;
        }

        return false;
    }

    std::unique_ptr<dummy_source> open(const std::string &params)
    {
        // Config is optional. In this case, defaults are used.
        uint64_t max_events = DEFAULT_MAX_EVENTS;
        uint64_t start = DEFAULT_START_VALUE;

        if(!params.empty())
        {
            try
            {
                auto open_params = nlohmann::json::parse(params);
                auto it = open_params.find("start");
                if(it != open_params.end())
                {
                    start = *it;
                }

                it = open_params.find("maxEvents");
                if(it != open_params.end())
                {
                    max_events = *it;
                }
            }
            catch(std::exception e)
            {
                m_lasterr = "wrong open params format";
                log_error(m_lasterr);
                return nullptr;
            }
        }

        return std::unique_ptr<dummy_source>(
                new dummy_source(max_events, start, m_jitter));
    }

    std::string m_lasterr = "";
    uint64_t m_jitter = DEFAULT_JITTER;
};

FALCOSECURITY_PLUGIN(dummy);
FALCOSECURITY_PLUGIN_EVENT_SOURCING(dummy, dummy_source);
FALCOSECURITY_PLUGIN_FIELD_EXTRACTION(dummy);
