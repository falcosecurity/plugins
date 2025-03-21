#include <plugin.h>
#include "async.tpp"

//////////////////////////
// Async capability
//////////////////////////

std::unique_ptr<falcosecurity::async_event_handler>
        s_async_handler[ASYNC_HANDLER_MAX];
static void *s_async_ctx;

std::vector<std::string> my_plugin::get_async_events()
{
    return ASYNC_EVENT_NAMES;
}

std::vector<std::string> my_plugin::get_async_event_sources()
{
    return ASYNC_EVENT_SOURCES;
}

// We need this API to start the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::start_async_events(
        std::shared_ptr<falcosecurity::async_event_handler_factory> f)
{
    for(int i = 0; i < ASYNC_HANDLER_MAX; i++)
    {
        s_async_handler[i] = std::move(f->new_handler());
    }

    // Implemented by GO worker.go
    m_logger.log("starting async go-worker",
                 falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);
    nlohmann::json j(m_cfg);
    s_async_ctx = StartWorker(generate_async_event<ASYNC_HANDLER_GO_WORKER>,
                              j.dump().c_str());
    return s_async_ctx != nullptr;
}

// We need this API to stop the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::stop_async_events() noexcept
{
    m_logger.log("stopping async go-worker",
                 falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);
    if(s_async_ctx != nullptr)
    {
        // Implemented by GO worker.go
        StopWorker(s_async_ctx);
        s_async_ctx = nullptr;

        for(int i = 0; i < ASYNC_HANDLER_MAX; i++)
        {
            s_async_handler[i].reset();
        }
    }
    return true;
}

void my_plugin::dump(
        std::unique_ptr<falcosecurity::async_event_handler> async_handler)
{
    m_logger.log(fmt::format("dumping plugin internal state: {} containers",
                             m_containers.size()),
                 falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);
    for(const auto &container : m_containers)
    {
        falcosecurity::events::asyncevent_e_encoder enc;
        enc.set_tid(1);
        nlohmann::json j(container.second);
        std::string msg = j.dump();
        enc.set_name(ASYNC_EVENT_NAME_ADDED);
        enc.set_data((void *)msg.c_str(), msg.size() + 1);

        enc.encode(async_handler->writer());
        async_handler->push();
    }
}

FALCOSECURITY_PLUGIN_ASYNC_EVENTS(my_plugin);
