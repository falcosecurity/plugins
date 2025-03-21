#include "cri.h"
#include "runc.h"

using namespace libsinsp::runc;

constexpr const cgroup_layout CRI_CGROUP_LAYOUT[] = {
        {"/", ""},                      // non-systemd containerd
        {"/crio-", ""},                 // non-systemd cri-o
        {"/cri-containerd-", ".scope"}, // systemd containerd
        {"/crio-", ".scope"},           // systemd cri-o
        {":cri-containerd:", ""}, // containerd without "SystemdCgroup = true"
        {"/docker-", ".scope"},   // systemd docker in cri-dockerd scenario
        {nullptr, nullptr}};

bool cri::resolve(const std::string& cgroup, std::string& container_id)
{
    return matches_runc_cgroup(cgroup, CRI_CGROUP_LAYOUT, container_id);
}