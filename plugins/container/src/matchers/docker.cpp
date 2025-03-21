#include "docker.h"
#include "runc.h"

using namespace libsinsp::runc;

constexpr const cgroup_layout DOCKER_CGROUP_LAYOUT[] = {
        {"/", ""},              // non-systemd docker
        {"/docker-", ".scope"}, // systemd docker
        {nullptr, nullptr}};

bool docker::resolve(const std::string& cgroup, std::string& container_id)
{
    return matches_runc_cgroup(cgroup, DOCKER_CGROUP_LAYOUT, container_id);
}