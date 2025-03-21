#include <gtest/gtest.h>
#include <matcher.h>

class container_cgroup : public testing::Test
{
    public:
    container_cgroup(): m_mgr(Engines{}) {}
    ~container_cgroup() {}
    matcher_manager m_mgr;
};

TEST_F(container_cgroup, containerd_cgroupfs)
{
    const std::string cgroup =
            "/kubepods/besteffort/podac04f3f2-1f2c-11e9-b015-1ebee232acfa/"
            "605439acbd4fb18c145069289094b17f17e0cfa938f78012d4960bc797305f22";
    const std::string expected_container_id = "605439acbd4f";

    std::string container_id;
    std::shared_ptr<container_info> info;
    EXPECT_TRUE(m_mgr.match_cgroup(cgroup, container_id, info));
    EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, crio_cgroupfs)
{
    const std::string cgroup =
            "/kubepods/besteffort/pod63b3ebfc-2890-11e9-8154-16bf8ef8d9dc/"
            "crio-"
            "73bfe475650de66df8e2affdc98d440dcbe84f8df83b6f75a68a82eb7026136a";
    const std::string expected_container_id = "73bfe475650d";

    std::string container_id;
    std::shared_ptr<container_info> info;
    EXPECT_TRUE(m_mgr.match_cgroup(cgroup, container_id, info));
    EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, crio_systemd)
{
    const std::string cgroup =
            "/kubepods.slice/kubepods-besteffort.slice/"
            "kubepods-besteffort-pod63b3ebfc_2890_11e9_8154_16bf8ef8d9dc.slice/"
            "crio-"
            "17d8c9eacc629f9945f304d89e9708c0c619649a484a215b240628319548a09f."
            "scope";
    const std::string expected_container_id = "17d8c9eacc62";

    std::string container_id;
    std::shared_ptr<container_info> info;
    EXPECT_TRUE(m_mgr.match_cgroup(cgroup, container_id, info));
    EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, docker_cgroupfs)
{
    const std::string cgroup =
            "/docker/"
            "7951fb549ab99e0722a949b6c121634e1f3a36b5bacbe5392991e3b12251e6b8";
    const std::string expected_container_id = "7951fb549ab9";

    std::string container_id;
    std::shared_ptr<container_info> info;
    EXPECT_TRUE(m_mgr.match_cgroup(cgroup, container_id, info));
    EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, docker_systemd)
{
    const std::string cgroup = "/docker.slice/"
                               "docker-"
                               "7951fb549ab99e0722a949b6c121634e1f3a36b5bacbe53"
                               "92991e3b12251e6b8.scope";
    const std::string expected_container_id = "7951fb549ab9";

    std::string container_id;
    std::shared_ptr<container_info> info;
    EXPECT_TRUE(m_mgr.match_cgroup(cgroup, container_id, info));
    EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, containerd_unknown)
{
    const std::string cgroup =
            "/kubepods-burstable-podbd12dd3393227d950605a2444b13c27a.slice:cri-"
            "containerd:"
            "d52db56a9c80d536a91354c0951c061187ca46249e64865a12703003d8f42366";
    const std::string expected_container_id = "d52db56a9c80";

    std::string container_id;
    std::shared_ptr<container_info> info;
    EXPECT_TRUE(m_mgr.match_cgroup(cgroup, container_id, info));
    EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, containerd)
{
    const std::string cgroup = "/default/test_container";
    const std::string expected_container_id = "test_contain"; // first 12 chars

    std::string container_id;
    std::shared_ptr<container_info> info;
    EXPECT_TRUE(m_mgr.match_cgroup(cgroup, container_id, info));
    EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, containerd_namespaced)
{
    const std::string cgroup = "/my_very_long_namespace-1.5/test_container";
    const std::string expected_container_id = "test_contain"; // first 12 chars

    std::string container_id;
    std::shared_ptr<container_info> info;
    EXPECT_TRUE(m_mgr.match_cgroup(cgroup, container_id, info));
    EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, non_container_cgroup)
{
    const std::string cgroup =
            "/user.slice/user-1000.slice/user@1000.service/init.scope";

    std::string container_id;
    std::shared_ptr<container_info> info;
    EXPECT_FALSE(m_mgr.match_cgroup(cgroup, container_id, info));
}