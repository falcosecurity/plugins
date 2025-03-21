#pragma once

#include <libworker.h>
#include <chrono>

enum async_handler_id {
    ASYNC_HANDLER_DEFAULT,
    ASYNC_HANDLER_GO_WORKER,
};

#define ASYNC_HANDLER_MAX (ASYNC_HANDLER_GO_WORKER + 1)

extern std::unique_ptr<falcosecurity::async_event_handler>
        s_async_handler[ASYNC_HANDLER_MAX];

static inline uint64_t get_current_time_ns(int sec_shift)
{
    std::chrono::nanoseconds ns =
            std::chrono::system_clock::now().time_since_epoch();
    return ns.count();
}

template<async_handler_id id>
void generate_async_event(const char *json, bool added)
{
    falcosecurity::events::asyncevent_e_encoder enc;
    enc.set_tid(1);
    std::string msg = json;
    if(added)
    {
        // leave ts=-1 (default value) to ensure that the event is grabbed asap
        enc.set_name(ASYNC_EVENT_NAME_ADDED);
    }
    else
    {
        // set ts = now + 1s to leave some space for enqueued syscalls to be
        // enriched
        enc.set_ts(get_current_time_ns(1));
        enc.set_name(ASYNC_EVENT_NAME_REMOVED);
    }
    enc.set_data((void *)msg.c_str(), msg.size() + 1);

    enc.encode(s_async_handler[id]->writer());
    s_async_handler[id]->push();
}