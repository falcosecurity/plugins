#include <gtest/gtest.h>
#include <plugin_config.h>

TEST(plugin_config, from_json)
{
    std::string config = R"({
  "engines": {
    "bpm": {
      "enabled": false
    },
    "containerd": {
      "enabled": true,
      "sockets": [
        "/run/containerd/containerd.sock"
      ]
    },
    "cri": {
      "enabled": true,
      "sockets": [
        "/run/crio/crio.sock"
      ]
    },
    "docker": {
      "enabled": true,
      "sockets": [
        "/var/run/docker.sock"
      ]
    },
    "libvirt_lxc": {
      "enabled": false
    },
    "podman": {
      "enabled": false,
      "sockets": [
        "/run/podman/podman.sock",
        "/run/user/1000/podman/podman.sock"
      ]
    }
  },
  "label_max_len": 120,
  "with_size": true
})";
    auto config_json = nlohmann::json::parse(config);

    auto cfg = config_json.get<PluginConfig>();
    EXPECT_TRUE(cfg.engines.cri.enabled);
    EXPECT_TRUE(cfg.engines.docker.enabled);
    EXPECT_TRUE(cfg.engines.containerd.enabled);
    EXPECT_TRUE(cfg.engines.lxc.enabled); // missing defaults to enabled

    EXPECT_FALSE(cfg.engines.podman.enabled);
    EXPECT_FALSE(cfg.engines.libvirt_lxc.enabled);
    EXPECT_FALSE(cfg.engines.bpm.enabled);

    EXPECT_TRUE(cfg.with_size);
    EXPECT_EQ(cfg.label_max_len, 120);
}

TEST(plugin_config, from_json_missing_engines)
{
    std::string config = R"({
  "label_max_len": 120,
  "with_size": true
})";
    auto config_json = nlohmann::json::parse(config);

    auto cfg = config_json.get<PluginConfig>();
    EXPECT_TRUE(cfg.engines.cri.enabled);
    EXPECT_TRUE(cfg.engines.docker.enabled);
    EXPECT_EQ(cfg.engines.docker.sockets[0],
              "/var/run/docker.sock"); // check that default sockets are added
    EXPECT_TRUE(cfg.engines.containerd.enabled);
    EXPECT_TRUE(cfg.engines.lxc.enabled);
    EXPECT_TRUE(cfg.engines.podman.enabled);
    EXPECT_TRUE(cfg.engines.libvirt_lxc.enabled);
    EXPECT_TRUE(cfg.engines.bpm.enabled);

    EXPECT_TRUE(cfg.with_size);
    EXPECT_EQ(cfg.label_max_len, 120);
}

TEST(plugin_config, from_json_empty_json)
{
    std::string config = R"({})";
    auto config_json = nlohmann::json::parse(config);

    auto cfg = config_json.get<PluginConfig>();
    EXPECT_TRUE(cfg.engines.cri.enabled);
    EXPECT_TRUE(cfg.engines.docker.enabled);
    EXPECT_EQ(cfg.engines.docker.sockets[0],
              "/var/run/docker.sock"); // check that default sockets are added
    EXPECT_TRUE(cfg.engines.containerd.enabled);
    EXPECT_TRUE(cfg.engines.lxc.enabled);
    EXPECT_TRUE(cfg.engines.podman.enabled);
    EXPECT_TRUE(cfg.engines.libvirt_lxc.enabled);
    EXPECT_TRUE(cfg.engines.bpm.enabled);

    EXPECT_FALSE(cfg.with_size);
    EXPECT_EQ(cfg.label_max_len, DEFAULT_LABEL_MAX_LEN);
}

TEST(plugin_config, to_json)
{
    std::string expected_config = R"({
  "engines": {
    "containerd": {
      "enabled": true,
      "sockets": [
        "/run/containerd/containerd.sock"
      ]
    },
    "cri": {
      "enabled": true,
      "sockets": [
        "/run/crio/crio.sock"
      ]
    },
    "docker": {
      "enabled": true,
      "sockets": [
        "/var/run/docker.sock"
      ]
    },
    "podman": {
      "enabled": false,
      "sockets": [
        "/run/podman/podman.sock",
        "/run/user/1000/podman/podman.sock"
      ]
    }
  },
  "host_root": "",
  "label_max_len": 120,
  "with_size": true
})";
    auto cfg = PluginConfig{};
    cfg.engines.cri.enabled = true;
    cfg.engines.cri.sockets.emplace_back("/run/crio/crio.sock");

    cfg.engines.containerd.enabled = true;
    cfg.engines.containerd.sockets.emplace_back(
            "/run/containerd/containerd.sock");

    cfg.engines.docker.enabled = true;
    cfg.engines.docker.sockets.emplace_back("/var/run/docker.sock");

    cfg.engines.podman.enabled = false;
    cfg.engines.podman.sockets.emplace_back("/run/podman/podman.sock");
    cfg.engines.podman.sockets.emplace_back(
            "/run/user/1000/podman/podman.sock");

    cfg.label_max_len = 120;
    cfg.with_size = true;

    nlohmann::json j(cfg);
    EXPECT_EQ(j.dump(2).c_str(), expected_config);
}