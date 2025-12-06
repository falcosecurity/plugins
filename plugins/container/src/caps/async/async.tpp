#pragma once

#include "container_info_json.h"

#include <libworker.h>

enum async_handler_id
{
    ASYNC_HANDLER_DEFAULT,
    ASYNC_HANDLER_GO_WORKER,
};

#define ASYNC_HANDLER_MAX (ASYNC_HANDLER_GO_WORKER + 1)

extern std::unique_ptr<falcosecurity::async_event_handler>
        s_async_handler[ASYNC_HANDLER_MAX];

static std::unordered_map<std::string, std::shared_ptr<const container_info>>
        s_preexisting_containers;

template<async_handler_id id>
void generate_async_event(const char *json, bool added, bool initial_state)
{
    falcosecurity::events::asyncevent_e_encoder enc;
    enc.set_tid(0); // not-existent tid
    std::string msg = json;
    if(added)
    {
        enc.set_name(ASYNC_EVENT_NAME_ADDED);
        // We are being called during initial `start_async_events`.
        // Update our internal cache immediately since:
        //     * we are called sinchronously
        //     * when our listening CAP will be triggered,
        //       we need pre-existing containers to be already cached.
        if(initial_state)
        {
            auto json_event = nlohmann::json::parse(json);
            auto cinfo = json_event.get<container_info::ptr_t>();
            s_preexisting_containers[cinfo->m_id] = cinfo;
        }
    }
    else
    {
        enc.set_name(ASYNC_EVENT_NAME_REMOVED);
    }
    enc.set_data((void *)msg.c_str(), msg.size() + 1);

    enc.encode(s_async_handler[id]->writer());
    s_async_handler[id]->push();
}
