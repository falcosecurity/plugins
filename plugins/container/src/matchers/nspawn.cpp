#include "nspawn.h"

#include <string_view>

namespace
{
// systemd places the containers started by systemd-nspawn in machine.slice,
// in a unit named after the (escaped) machine name:
// - machine-<name>.scope, when systemd-nspawn registers the container itself
// - systemd-nspawn@<name>.service, when the container is started through the
//   systemd-nspawn@.service template unit (e.g. by `machinectl start`)
// On the user manager, machine.slice lives under user@<uid>.service.
constexpr std::string_view MACHINE_SLICE = "/machine.slice/";

struct unit_layout
{
    std::string_view prefix;
    std::string_view suffix;
};

constexpr unit_layout NSPAWN_UNIT_LAYOUT[] = {
        {"machine-", ".scope"},
        {"systemd-nspawn@", ".service"},
};

// With the unified cgroup hierarchy, systemd-nspawn moves the container into
// a "payload" sub-cgroup of the unit (and itself into "supervisor", when it
// keeps the unit). Only the payload, and the cgroups the container creates
// below it, belong to the container: systemd-nspawn itself stays on the host.
// See src/nspawn/nspawn-cgroup.c in systemd.
constexpr std::string_view PAYLOAD = "/payload";

int hex_value(char c)
{
    if(c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if(c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if(c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

// Reverse the unit name escaping done by systemd (see unit_name_unescape()):
// every "\xNN" sequence is replaced by the byte it encodes, e.g. "\x2d" by '-'.
// Return false on a malformed escape sequence.
bool unescape_unit_name(std::string_view escaped, std::string& name)
{
    name.clear();
    for(size_t i = 0; i < escaped.size(); i++)
    {
        if(escaped[i] != '\\')
        {
            name += escaped[i];
            continue;
        }
        if(escaped.size() - i < 4 || escaped[i + 1] != 'x')
        {
            return false;
        }
        int hi = hex_value(escaped[i + 2]);
        int lo = hex_value(escaped[i + 3]);
        if(hi < 0 || lo < 0)
        {
            return false;
        }
        name += static_cast<char>((hi << 4) | lo);
        i += 3;
    }
    return !name.empty();
}

// Check whether the cgroup has, starting at unit_start, a systemd-nspawn unit
// followed by its payload cgroup. If so, set machine_name to the unescaped
// machine name and return true.
bool match_nspawn_unit(const std::string& cgroup, size_t unit_start,
                       std::string& machine_name)
{
    size_t unit_end = cgroup.find('/', unit_start);
    if(unit_end == std::string::npos ||
       cgroup.compare(unit_end, PAYLOAD.size(), PAYLOAD) != 0)
    {
        return false;
    }
    size_t payload_end = unit_end + PAYLOAD.size();
    if(payload_end != cgroup.size() && cgroup[payload_end] != '/')
    {
        return false;
    }

    std::string_view unit(cgroup.data() + unit_start, unit_end - unit_start);
    for(const auto& layout : NSPAWN_UNIT_LAYOUT)
    {
        if(unit.size() > layout.prefix.size() + layout.suffix.size() &&
           unit.starts_with(layout.prefix) && unit.ends_with(layout.suffix))
        {
            auto escaped = unit.substr(layout.prefix.size(),
                                       unit.size() - layout.prefix.size() -
                                               layout.suffix.size());
            return unescape_unit_name(escaped, machine_name);
        }
    }
    return false;
}
} // namespace

bool nspawn::resolve(const std::string& cgroup, std::string& container_id)
{
    // Look for the innermost machine.slice first, so that a container nested
    // in a systemd-nspawn container is reported instead of the outer one.
    size_t pos = cgroup.rfind(MACHINE_SLICE);
    while(pos != std::string::npos)
    {
        std::string machine_name;
        if(match_nspawn_unit(cgroup, pos + MACHINE_SLICE.size(), machine_name))
        {
            container_id = machine_name;
            return true;
        }
        if(pos == 0)
        {
            break;
        }
        pos = cgroup.rfind(MACHINE_SLICE, pos - 1);
    }
    return false;
}

container_info::ptr_t nspawn::to_container(const std::string& container_id)
{
    auto ctr = std::make_shared<container_info>();
    ctr->m_id = container_id;
    // The machine name is the only name a systemd-nspawn container has.
    ctr->m_name = container_id;
    ctr->m_type = CT_NSPAWN;
    return ctr;
}
