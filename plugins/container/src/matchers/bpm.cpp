#include "bpm.h"
#include <cstring>

bool bpm::resolve(const std::string& cgroup, std::string& container_id)
{
    //
    // Non-systemd and systemd BPM
    //
    auto pos = cgroup.find("bpm-");
    if(pos != std::string::npos)
    {
        auto id_start = pos + sizeof("bpm-") - 1;
        auto id_end = cgroup.find(".scope", id_start);
        auto id = cgroup.substr(id_start, id_end - id_start);

        // As of BPM v1.0.3, the container ID is only allowed to contain the
        // following chars see
        // https://github.com/cloudfoundry-incubator/bpm-release/blob/v1.0.3/src/bpm/jobid/encoding.go
        if(!id.empty() &&
           strspn(id.c_str(), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"
                              "WXYZ0123456789._-") == id.size())
        {
            container_id = id;
            return true;
        }
    }
    return false;
}

std::shared_ptr<container_info>
bpm::to_container(const std::string& container_id)
{
    auto ctr = std::make_shared<container_info>();
    ctr->m_id = container_id;
    ctr->m_type = CT_BPM;
    return ctr;
}