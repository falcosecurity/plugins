#include <plugin.h>

//////////////////////////
// Listening capability
//////////////////////////

bool my_plugin::capture_open(const falcosecurity::capture_listen_input& in)
{
    m_logger.log("enriching initial thread table entries",
                 falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);
    auto& tr = in.get_table_reader();
    auto& tw = in.get_table_writer();
    m_threads_table.iterate_entries(
            tr,
            [this, tr, tw](const falcosecurity::table_entry& e)
            {
                try
                {
                    on_new_process(e, tr, tw);
                    return true;
                }
                catch(falcosecurity::plugin_exception& e)
                {
                    m_logger.log(
                            fmt::format(
                                    "cannot attach container_id to process: {}",
                                    e.what()),
                            falcosecurity::_internal::SS_PLUGIN_LOG_SEV_ERROR);
                    return false;
                }
            });
    return true;
}

bool my_plugin::capture_close(const falcosecurity::capture_listen_input& in)
{
    return true;
}

FALCOSECURITY_PLUGIN_CAPTURE_LISTENING(my_plugin);