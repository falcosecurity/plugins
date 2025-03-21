#include "plugin.h"

#define CONTAINER_TABLE_NAME "containers"
#define CONTAINER_EXPOSED_FIELD_IP "ip"
#define CONTAINER_EXPOSED_FIELD_USER "user"

enum
{
    CONTAINER_FIELD_IP,
    CONTAINER_FIELD_USER,
    CONTAINER_FIELD_MAX,
};

using namespace falcosecurity::_internal;

static std::vector<ss_plugin_table_fieldinfo> fields = {
        {CONTAINER_EXPOSED_FIELD_IP, SS_PLUGIN_ST_STRING, true},
        {CONTAINER_EXPOSED_FIELD_USER, SS_PLUGIN_ST_STRING, true},
};

static const char* reader_get_table_name(ss_plugin_table_t* t)
{
    return CONTAINER_TABLE_NAME;
}

static uint64_t reader_get_table_size(ss_plugin_table_t* t)
{
    auto containers = static_cast<std::unordered_map<
            std::string, std::shared_ptr<const container_info>>*>(t);
    return containers->size();
}

static ss_plugin_table_entry_t*
reader_get_table_entry(ss_plugin_table_t* t, const ss_plugin_state_data* key)
{
    auto containers = static_cast<std::unordered_map<
            std::string, std::shared_ptr<const container_info>>*>(t);
    if(containers->count(key->str) == 0)
    {
        return nullptr;
    }
    return (ss_plugin_table_entry_t*)containers->at(key->str).get();
}

static ss_plugin_rc reader_read_entry_field(ss_plugin_table_t* t,
                                            ss_plugin_table_entry_t* e,
                                            const ss_plugin_table_field_t* f,
                                            ss_plugin_state_data* out)
{
    auto ctr = static_cast<const container_info*>(e);
    switch((uintptr_t)f)
    {
    case CONTAINER_FIELD_IP + 1:
        out->str = ctr->m_container_ip.c_str();
        break;
    case CONTAINER_FIELD_USER + 1:
        out->str = ctr->m_container_user.c_str();
        break;
    default:
        return SS_PLUGIN_FAILURE;
    }
    return SS_PLUGIN_SUCCESS;
}

static void reader_release_table_entry(ss_plugin_table_t* t,
                                       ss_plugin_table_entry_t* e)
{
    // Unsupported for now.
}

static ss_plugin_bool
reader_iterate_entries(ss_plugin_table_t* t, ss_plugin_table_iterator_func_t it,
                       ss_plugin_table_iterator_state_t* s)
{
    auto containers = static_cast<std::unordered_map<
            std::string, std::shared_ptr<const container_info>>*>(t);
    bool ret = true;
    for(const auto& c : *containers)
    {
        ret = it(s, (ss_plugin_table_entry_t*)c.second.get());
        if(!ret)
        {
            break;
        }
    }
    return ret;
}

static const ss_plugin_table_fieldinfo* list_table_fields(ss_plugin_table_t* t,
                                                          uint32_t* nfields)
{
    *nfields = fields.size();
    return fields.data();
}

static ss_plugin_table_field_t* get_table_field(ss_plugin_table_t* t,
                                                const char* name,
                                                ss_plugin_state_type data_type)
{
    for(unsigned long i = 0; i < fields.size(); i++)
    {
        if(strcmp(fields[i].name, name) == 0)
        {
            // note: shifted by 1 so that we never return 0 (interpreted as
            // NULL)
            return (ss_plugin_table_field_t*)(i + 1);
        }
    }
    return nullptr;
}

static ss_plugin_table_field_t* add_table_field(ss_plugin_table_t* _t,
                                                const char* name,
                                                ss_plugin_state_type data_type)
{
    // Unsupported for now.
    return nullptr;
}

static ss_plugin_rc clear_table(ss_plugin_table_t* t)
{
    auto containers = static_cast<std::unordered_map<
            std::string, std::shared_ptr<const container_info>>*>(t);
    containers->clear();
    return SS_PLUGIN_SUCCESS;
}

static ss_plugin_rc erase_table_entry(ss_plugin_table_t* t,
                                      const ss_plugin_state_data* key)
{
    auto containers = static_cast<std::unordered_map<
            std::string, std::shared_ptr<const container_info>>*>(t);
    if(containers->count(key->str) == 0)
    {
        return SS_PLUGIN_FAILURE;
    }
    containers->erase(key->str);
    return SS_PLUGIN_SUCCESS;
}

static ss_plugin_table_entry_t* create_table_entry(ss_plugin_table_t* t)
{
    // Unsupported for now.
    return nullptr;
}

static void destroy_table_entry(ss_plugin_table_t* t,
                                ss_plugin_table_entry_t* e)
{
    // Unsupported for now.
}

static ss_plugin_table_entry_t* add_table_entry(ss_plugin_table_t* t,
                                                const ss_plugin_state_data* key,
                                                ss_plugin_table_entry_t* e)
{
    // Unsupported for now.
    return nullptr;
}

static ss_plugin_rc write_entry_field(ss_plugin_table_t* _t,
                                      ss_plugin_table_entry_t* _e,
                                      const ss_plugin_table_field_t* _f,
                                      const ss_plugin_state_data* in)
{
    // Unsupported for now.
    return SS_PLUGIN_NOT_SUPPORTED;
}

static ss_plugin_table_reader_vtable_ext* get_reader_ext()
{
    static ss_plugin_table_reader_vtable_ext reader_vtable;
    reader_vtable.get_table_name = reader_get_table_name;
    reader_vtable.get_table_size = reader_get_table_size;
    reader_vtable.get_table_entry = reader_get_table_entry;
    reader_vtable.read_entry_field = reader_read_entry_field;
    reader_vtable.release_table_entry = reader_release_table_entry;
    reader_vtable.iterate_entries = reader_iterate_entries;
    return &reader_vtable;
}

static ss_plugin_table_fields_vtable_ext* get_fields_ext()
{
    static ss_plugin_table_fields_vtable_ext fields_vtable;
    fields_vtable.list_table_fields = list_table_fields;
    fields_vtable.add_table_field = add_table_field;
    fields_vtable.get_table_field = get_table_field;
    return &fields_vtable;
}

static ss_plugin_table_writer_vtable_ext* get_writer_ext()
{
    static ss_plugin_table_writer_vtable_ext writer_vtable;
    writer_vtable.clear_table = clear_table;
    writer_vtable.erase_table_entry = erase_table_entry;
    writer_vtable.create_table_entry = create_table_entry;
    writer_vtable.destroy_table_entry = destroy_table_entry;
    writer_vtable.add_table_entry = add_table_entry;
    writer_vtable.write_entry_field = write_entry_field;

    return &writer_vtable;
}

ss_plugin_table_input& my_plugin::get_table()
{
    using st = falcosecurity::state_value_type;

    static ss_plugin_table_input input;
    input.name = CONTAINER_TABLE_NAME;
    input.key_type = st::SS_PLUGIN_ST_STRING;
    input.table = (void*)&m_containers;

    input.reader_ext = get_reader_ext();
    input.reader.get_table_name = input.reader_ext->get_table_name;
    input.reader.get_table_size = input.reader_ext->get_table_size;
    input.reader.get_table_entry = input.reader_ext->get_table_entry;
    input.reader.read_entry_field = input.reader_ext->read_entry_field;

    input.writer_ext = get_writer_ext();
    input.writer.clear_table = input.writer_ext->clear_table;
    input.writer.erase_table_entry = input.writer_ext->erase_table_entry;
    input.writer.create_table_entry = input.writer_ext->create_table_entry;
    input.writer.destroy_table_entry = input.writer_ext->destroy_table_entry;
    input.writer.add_table_entry = input.writer_ext->add_table_entry;
    input.writer.write_entry_field = input.writer_ext->write_entry_field;

    input.fields_ext = get_fields_ext();
    input.fields.list_table_fields = input.fields_ext->list_table_fields;
    input.fields.get_table_field = input.fields_ext->get_table_field;
    input.fields.add_table_field = input.fields_ext->add_table_field;
    return input;
}