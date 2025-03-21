#include "static_container.h"

// This is taken from libsinsp/utils.cpp
static inline void split_container_image(const std::string& image,
                                         std::string& hostname,
                                         std::string& port, std::string& name,
                                         std::string& tag, std::string& digest)
{
    auto split = [](const std::string& src, std::string& part1,
                    std::string& part2, const std::string& sep)
    {
        size_t pos = src.find(sep);
        if(pos != std::string::npos)
        {
            part1 = src.substr(0, pos);
            part2 = src.substr(pos + 1);
            return true;
        }
        return false;
    };

    std::string hostport, rem, rem2, repo;

    hostname = port = name = tag = digest = "";

    if(split(image, hostport, rem, "/"))
    {
        repo = hostport + "/";
        if(!split(hostport, hostname, port, ":"))
        {
            hostname = hostport;
            port = "";
        }
    }
    else
    {
        hostname = "";
        port = "";
        rem = image;
    }

    if(split(rem, rem2, digest, "@"))
    {
        if(!split(rem2, name, tag, ":"))
        {
            name = rem2;
            tag = "";
        }
    }
    else
    {
        digest = "";
        if(!split(rem, name, tag, ":"))
        {
            name = rem;
            tag = "";
        }
    }

    name = repo + name;
}

static_container::static_container(const std::string& id,
                                   const std::string& name,
                                   const std::string& image)
{
    m_static_container_info = std::make_shared<container_info>();
    m_static_container_info->m_id = id;
    m_static_container_info->m_type = CT_STATIC;
    m_static_container_info->m_name = name;
    m_static_container_info->m_image = image;
    std::string hostname;
    std::string port;
    split_container_image(m_static_container_info->m_image, hostname, port,
                          m_static_container_info->m_imagerepo,
                          m_static_container_info->m_imagetag,
                          m_static_container_info->m_imagedigest);
}

bool static_container::resolve(const std::string& cgroup,
                               std::string& container_id)
{
    container_id = m_static_container_info->m_id;
    return true;
}

std::shared_ptr<container_info>
static_container::to_container(const std::string& container_id)
{
    return m_static_container_info;
}