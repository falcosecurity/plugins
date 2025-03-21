#include <filesystem>
#include "plugin_config.h"

void from_json(const nlohmann::json& j, StaticEngine& engine)
{
    engine.enabled = j.value("enabled", false);
    engine.name = j.value("container_name", "");
    engine.id = j.value("container_id", "");
    engine.image = j.value("container_image", "");
}

void from_json(const nlohmann::json& j, SimpleEngine& engine)
{
    engine.enabled = j.value("enabled", true);
}

void from_json(const nlohmann::json& j, SocketsEngine& engine)
{
    engine.enabled = j.value("enabled", true);
    engine.sockets = j.value("sockets", std::vector<std::string>{});
}

void from_json(const nlohmann::json& j, Engines& engines)
{
    engines.bpm = j.value("bpm", SimpleEngine{});
    engines.lxc = j.value("lxc", SimpleEngine{});
    engines.libvirt_lxc = j.value("libvirt_lxc", SimpleEngine{});
    engines.static_ctr = j.value("static", StaticEngine{});

    engines.docker = j.value("docker", SocketsEngine{});
    engines.podman = j.value("podman", SocketsEngine{});
    engines.cri = j.value("cri", SocketsEngine{});
    engines.containerd = j.value("containerd", SocketsEngine{});
}

void from_json(const nlohmann::json& j, PluginConfig& cfg)
{
    cfg.label_max_len = j.value("label_max_len", DEFAULT_LABEL_MAX_LEN);
    cfg.with_size = j.value("with_size", false);
    cfg.engines = j.value("engines", Engines{});

    // Set default sockets if emtpy
    if(cfg.engines.docker.sockets.empty())
    {
        cfg.engines.docker.sockets.emplace_back("/var/run/docker.sock");
    }
    if(cfg.engines.podman.sockets.empty())
    {
        cfg.engines.podman.sockets.emplace_back("/run/podman/podman.sock");
        try
        {
            for(const auto& entry : std::filesystem::directory_iterator(
                        cfg.host_root + "/run/user"))
            {
                if(entry.is_directory())
                {
                    if(std::filesystem::exists(entry.path().string() +
                                               "/podman/podman.sock"))
                    {
                        // Remove host root since it will be later added by
                        // go-worker itself
                        auto root = entry.path().string().substr(
                                cfg.host_root.length());
                        cfg.engines.podman.sockets.emplace_back(
                                root + "/podman/podman.sock");
                    }
                }
            }
        }
        catch(...)
        {
            // No error; perhaps /run/user does not exist.
        }
    }
    if(cfg.engines.cri.sockets.empty())
    {
        cfg.engines.cri.sockets.emplace_back("/run/containerd/containerd.sock");
        cfg.engines.cri.sockets.emplace_back("/run/crio/crio.sock");
        cfg.engines.cri.sockets.emplace_back(
                "/run/k3s/containerd/containerd.sock");
        cfg.engines.cri.sockets.emplace_back(
                "/run/host-containerd/containerd.sock");
    }
    if(cfg.engines.containerd.sockets.empty())
    {
        cfg.engines.containerd.sockets.emplace_back(
                "/run/host-containerd/containerd.sock"); // bottlerocket host
                                                         // containers socket
    }
}

void to_json(nlohmann::json& j, const Engines& engines)
{
    j = nlohmann::json{{"docker",
                        {{"enabled", engines.docker.enabled},
                         {"sockets", engines.docker.sockets}}},
                       {"podman",
                        {{"enabled", engines.podman.enabled},
                         {"sockets", engines.podman.sockets}}},
                       {"cri",
                        {{"enabled", engines.cri.enabled},
                         {"sockets", engines.cri.sockets}}},
                       {"containerd",
                        {{"enabled", engines.containerd.enabled},
                         {"sockets", engines.containerd.sockets}}}};
}

void to_json(nlohmann::json& j, const PluginConfig& cfg)
{
    j["label_max_len"] = cfg.label_max_len;
    j["with_size"] = cfg.with_size;
    j["host_root"] = cfg.host_root;
    j["engines"] = cfg.engines;
}
