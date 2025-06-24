#include <gtest/gtest.h>
#include <container_info.h>

TEST(container_info_json, null_healthcheck)
{
    std::string json = R"({
    "container": {
        "type": 0,
        "id": "fee3a77211e1",
        "User": "root",
        "cni_json": "",
        "cpu_period": 100000,
        "cpu_quota": 100000,
        "cpu_shares": 1024,
        "cpuset_cpu_count": 0,
        "created_time": 1749101763,
        "env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TZ=Asia/Shanghai"
        ],
        "full_id": "*",
        "host_ipc": false,
        "host_network": true,
        "host_pid": true,
        "ip": "",
        "size": -1,
        "is_pod_sandbox": false,
        "labels": {

        },
        "memory_limit": 2147483648,
        "swap_limit": 4294967296,
        "pod_sandbox_id": "",
        "privileged": true,
        "pod_sandbox_labels": null,
        "port_mappings": [

        ],
        "Mounts": [

        ],
        "Healthcheck": {
            "exe": "/usr/bin/healthcheck",
            "args": null
        }
    }
})";
    auto json_event = nlohmann::json::parse(json);
    ASSERT_NO_THROW(json_event.get<std::shared_ptr<container_info>>());
}