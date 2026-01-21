#include "runc.h"

#include <string_view>

namespace
{
const size_t CONTAINER_ID_LENGTH = 64;
const size_t REPORTED_CONTAINER_ID_LENGTH = 12;
const char *CONTAINER_ID_VALID_CHARACTERS = "0123456789abcdefABCDEF";

static_assert(
        REPORTED_CONTAINER_ID_LENGTH <= CONTAINER_ID_LENGTH,
        "Reported container ID length cannot be longer than actual length");
} // namespace

namespace libsinsp
{
namespace runc
{

inline static bool endswith(std::string_view s, std::string_view suffix)
{
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// check if cgroup ends with <prefix><container_id><suffix>
// If true, set <container_id> to a truncated version of the id and return true.
// Otherwise return false and leave container_id unchanged
//
// Using std::string_view for prefix and suffix avoids temporary std::string
// allocations when called with const char* from cgroup_layout structs.
bool match_one_container_id(const std::string &cgroup, std::string_view prefix,
                            std::string_view suffix, std::string &container_id,
                            bool is_containerd)
{
    size_t start_pos =
            cgroup.rfind(prefix.data(), std::string::npos, prefix.size());
    if(start_pos == std::string::npos)
    {
        return false;
    }
    start_pos += prefix.size();

    // For empty suffix, end_pos should be at the end of the string
    size_t end_pos;
    if(suffix.empty())
    {
        end_pos = cgroup.size();
    }
    else
    {
        end_pos = cgroup.rfind(suffix.data(), std::string::npos, suffix.size());
        if(end_pos == std::string::npos)
        {
            return false;
        }
    }

    if(end_pos - start_pos == CONTAINER_ID_LENGTH &&
       cgroup.find_first_not_of(CONTAINER_ID_VALID_CHARACTERS, start_pos) >=
               CONTAINER_ID_LENGTH)
    {
        // Use assign() instead of substr() to potentially reuse existing
        // capacity in container_id
        container_id.assign(cgroup, start_pos, REPORTED_CONTAINER_ID_LENGTH);
        return true;
    }

    // In some container runtimes the container the container id is not
    // necessarly CONTAINER_ID_LENGTH long and can be arbitrarly defined.
    // To keep it simple we only discard the container id > of
    // CONTAINER_ID_LENGTH.
    if(end_pos - start_pos > CONTAINER_ID_LENGTH || end_pos - start_pos == 0)
    {
        return false;
    }

    // For containerd, make sure to skip systemd host cgroups
    if(is_containerd && !endswith(cgroup, ".service") &&
       !endswith(cgroup, ".slice") && !endswith(cgroup, ".scope"))
    {
        const size_t reported_len =
                end_pos - start_pos >= REPORTED_CONTAINER_ID_LENGTH
                        ? REPORTED_CONTAINER_ID_LENGTH
                        : end_pos - start_pos;
        // Use assign() instead of substr() to potentially reuse existing
        // capacity in container_id
        container_id.assign(cgroup, start_pos, reported_len);
        return true;
    }

    return false;
}

bool matches_runc_cgroup(const std::string &cgroup,
                         const libsinsp::runc::cgroup_layout *layout,
                         std::string &container_id, bool is_containerd)
{
    for(size_t i = 0; layout[i].prefix && layout[i].suffix; ++i)
    {
        if(match_one_container_id(cgroup, layout[i].prefix, layout[i].suffix,
                                  container_id, is_containerd))
        {
            return true;
        }
    }
    return false;
}
} // namespace runc
} // namespace libsinsp