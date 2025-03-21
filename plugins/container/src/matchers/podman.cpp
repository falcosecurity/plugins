#include "podman.h"
#include "runc.h"

using namespace libsinsp::runc;

constexpr const cgroup_layout ROOT_PODMAN_CGROUP_LAYOUT[] = {
        {"/libpod-", ".scope"},           // podman
        {"/libpod-", ".scope/container"}, // podman
        {"/libpod-", ""},                 // non-systemd podman, e.g. on alpine
        {nullptr, nullptr}};

bool podman::resolve(const std::string& cgroup, std::string& container_id)
{
    return matches_runc_cgroup(cgroup, ROOT_PODMAN_CGROUP_LAYOUT, container_id);
}