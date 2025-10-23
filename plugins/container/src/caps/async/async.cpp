#include <plugin.h>
#include "async.tpp"

//////////////////////////
// Async capability
//////////////////////////

std::unique_ptr<falcosecurity::async_event_handler>
        s_async_handler[ASYNC_HANDLER_MAX];

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
    // We are already started. This can happen:
    // * if `start_async_events` is called multiple times
    // * during Falco hot reload dry-run checks; in that scenario,
    //   the same library object gets opened once again, thus a new `my_plugin`
    //   instance is created,
    //   and all static variables are shared. Just return true and do nothing.
    if(s_async_handler[ASYNC_HANDLER_DEFAULT] != nullptr)
    {
        return true;
    }

    for(int i = 0; i < ASYNC_HANDLER_MAX; i++)
    {
        s_async_handler[i] = std::move(f->new_handler());
    }

    // Implemented by GO worker.go
    m_logger.log("starting async go-worker",
                 falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);
    nlohmann::json j(m_cfg);

    const char *enabled_engines = nullptr;
    const char *err = nullptr;

    m_async_ctx = StartWorker(generate_async_event<ASYNC_HANDLER_GO_WORKER>,
                              j.dump().c_str(), &enabled_engines, &err);
    m_logger.log(fmt::format("attached engine sockets: {}", enabled_engines),
                 falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);

    if(err)
    {
        m_logger.log(fmt::format("failed to start async go-worker: {}", err),
                     falcosecurity::_internal::SS_PLUGIN_LOG_SEV_ERROR);
        free((void *)err);
    }

    free((void *)enabled_engines);

    // Merge back pre-existing containers to our cache
    for(const auto &c : s_preexisting_containers)
    {
        m_containers.insert(c);
        m_logger.log(fmt::format("Added pre-existing container: {}", c.first),
                     falcosecurity::_internal::SS_PLUGIN_LOG_SEV_TRACE);
    }

    return m_async_ctx != nullptr;
}

// We need this API to stop the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::stop_async_events() noexcept
{
    m_logger.log("stopping async go-worker",
                 falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);
    if(m_async_ctx != nullptr)
    {
        // Implemented by GO worker.go
        StopWorker(m_async_ctx);
        m_async_ctx = nullptr;

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
