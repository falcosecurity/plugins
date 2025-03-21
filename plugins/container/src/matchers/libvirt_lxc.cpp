#include "libvirt_lxc.h"

bool libvirt_lxc::resolve(const std::string& cgroup, std::string& container_id)
{
    //
    // Non-systemd libvirt-lxc
    //
    size_t pos = cgroup.find(".libvirt-lxc");
    if(pos != std::string::npos &&
       pos == cgroup.length() - sizeof(".libvirt-lxc") + 1)
    {
        size_t pos2 = cgroup.find_last_of("/");
        if(pos2 != std::string::npos)
        {
            container_id = cgroup.substr(pos2 + 1, pos - pos2 - 1);
            return true;
        }
    }

    //
    // systemd libvirt-lxc:
    //
    pos = cgroup.find("-lxc\\x2");
    if(pos != std::string::npos)
    {
        // For cgroups like:
        // /machine.slice/machine-lxc\x2d2293906\x2dlibvirt\x2dcontainer.scope/libvirt,
        // account for /libvirt below.
        std::string delimiter =
                (cgroup.find(".scope/libvirt") != std::string::npos)
                        ? ".scope/libvirt"
                        : ".scope";
        size_t pos2 = cgroup.find(delimiter);
        if(pos2 != std::string::npos &&
           pos2 == cgroup.length() - delimiter.length())
        {
            container_id = cgroup.substr(pos + sizeof("-lxc\\x2"),
                                         pos2 - pos - sizeof("-lxc\\x2"));
            return true;
        }
    }

    //
    // Legacy libvirt-lxc
    //
    pos = cgroup.find("/libvirt/lxc/");
    if(pos != std::string::npos)
    {
        container_id = cgroup.substr(pos + sizeof("/libvirt/lxc/") - 1);
        return true;
    }
    return false;
}

std::shared_ptr<container_info>
libvirt_lxc::to_container(const std::string& container_id)
{
    auto ctr = std::make_shared<container_info>();
    ctr->m_id = container_id;
    ctr->m_type = CT_LIBVIRT_LXC;
    return ctr;
}