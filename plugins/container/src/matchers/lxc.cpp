#include "lxc.h"

constexpr const std::string_view LXC_CGROUP_LAYOUT[] = {
        "/lxc/",         // non-systemd
        "/lxc.payload/", // systemd
        "/lxc.payload.", // lxc4.0 layout:
        // https://linuxcontainers.org/lxc/news/2020_03_25_13_03.html
};

bool lxc::resolve(const std::string& cgroup, std::string& container_id)
{
    for(const auto& cgroup_layout : LXC_CGROUP_LAYOUT)
    {
        size_t pos = cgroup.find(cgroup_layout);
        if(pos != std::string::npos)
        {
            auto id_start = pos + cgroup_layout.length();
            auto id_end = cgroup.find('/', id_start);
            container_id = cgroup.substr(id_start, id_end - id_start);
            return true;
        }
    }
    return false;
}

std::shared_ptr<container_info>
lxc::to_container(const std::string& container_id)
{
    auto ctr = std::make_shared<container_info>();
    ctr->m_id = container_id;
    ctr->m_type = CT_LXC;
    return ctr;
}