#include "containerd.h"
#include "runc.h"
#include <reflex/matcher.h>

using namespace libsinsp::runc;

static reflex::Pattern pattern("/([A-Za-z0-9]+(?:[._-](?:[A-Za-z0-9]+))*)/");

containerd::containerd(): m_matcher(pattern) {}

bool containerd::resolve(const std::string& cgroup, std::string& container_id)
{
    // Containers created via ctr
    // use a cgroup path like: `0::/namespace/container_id`
    // Since we cannot know the namespace in advance, we try to
    // extract it from the cgroup path by following provided regex,
    // and use that to eventually extract the container id.
    m_matcher.input(cgroup);
    if(m_matcher.find())
    {
        const auto containerd_namespace =
                std::string(m_matcher[0].first, m_matcher[0].second);
        // ctr places a container right below its namespace, and a container
        // id cannot contain '/'. Skip deeper cgroups, like the ones systemd
        // units create below themselves (e.g.
        // /machine.slice/machine-qemu\x2d1\x2dvm.scope/libvirt/emulator for a
        // libvirt VM), that would otherwise be taken for a containerd
        // container named after the unit.
        const auto id_start = cgroup.rfind(containerd_namespace) +
                              containerd_namespace.size();
        if(cgroup.find('/', id_start) != std::string::npos)
        {
            return false;
        }
        const cgroup_layout CONTAINERD_CGROUP_LAYOUT[] = {
                {containerd_namespace.c_str(), ""}, {nullptr, nullptr}};
        return matches_runc_cgroup(cgroup, CONTAINERD_CGROUP_LAYOUT,
                                   container_id, true);
    }
    return false;
}