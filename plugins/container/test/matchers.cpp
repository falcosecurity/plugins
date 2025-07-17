#include <gtest/gtest.h>
#include <matcher.h>
#include <container_info.h>
#include <plugin_config.h>

// Test case structure for detect_podman tests
struct matchers_test_case
{
    std::string name;
    std::string cgroup;
    std::string expected_container_id;
    bool should_match;
};

// Custom PrintTo function for readable test parameter output
void PrintTo(const matchers_test_case& test_case, std::ostream* os)
{
    *os << "Test: " << test_case.name
        << " | Expected Container ID: " << test_case.expected_container_id;
    *os << " | Cgroup: " << test_case.cgroup;
    *os << " | Should Match: " << (test_case.should_match ? "true" : "false");
    *os << " | Expected Container ID: " << test_case.expected_container_id;
}

// Custom test name generator
std::string
test_name_generator(const testing::TestParamInfo<matchers_test_case>& info)
{
    return info.param.name;
}

// Parametrized test for detect_podman
class matchers_test : public testing::TestWithParam<matchers_test_case>
{
    protected:
    matcher_manager m_mgr;

    public:
    matchers_test(): m_mgr(Engines{}) {}
};

TEST_P(matchers_test, detect_container_id)
{
    const auto& test_case = GetParam();

    std::string container_id;
    container_info::ptr_t info;
    EXPECT_EQ(m_mgr.match_cgroup(test_case.cgroup, container_id, info),
              test_case.should_match);

    if(test_case.should_match)
    {
        EXPECT_EQ(test_case.expected_container_id, container_id);
    }
}

INSTANTIATE_TEST_SUITE_P(
        detect_container_id, matchers_test,
        testing::ValuesIn(std::vector<matchers_test_case>{
                // Root podman containers
                {.name = "root_libpod_no_scope",
                 .cgroup = "/system.slice/"
                           "libpod-"
                           "1234567890abcdef1234567890abcdef1234567890abcdef123"
                           "4567890abcdef",
                 .expected_container_id = "1234567890ab",
                 .should_match = true},
                {.name = "root_libpod_scope",
                 .cgroup = "/system.slice/"
                           "libpod-"
                           "1234567890abcdef1234567890abcdef1234567890abcdef123"
                           "4567890abcdef."
                           "scope",
                 .expected_container_id = "1234567890ab",
                 .should_match = true},
                {.name = "root_libpod_cgroup_mode_split_no_scope",
                 .cgroup = "/system.slice/"
                           "system-ceph-f952f5be-565c-11f0-ab72-0affea283157."
                           "slice/"
                           "ceph-f952f5be-565c-11f0-ab72-0affea283157@mon.ip-"
                           "10-0-25-96.service/"
                           "libpod-payload-"
                           "9cc35a907a1e4e7ac8c021758b2bb28db60b3a787115f9114a6"
                           "41bf44f8ba99b",
                 .expected_container_id = "9cc35a907a1e",
                 .should_match = true},
                {.name = "root_libpod_cgroup_mode_split_scope",
                 .cgroup = "/system.slice/"
                           "system-ceph-f952f5be-565c-11f0-ab72-0affea283157."
                           "slice/"
                           "ceph-f952f5be-565c-11f0-ab72-0affea283157@mon.ip-"
                           "10-0-25-96.service/"
                           "libpod-payload-"
                           "9cc35a907a1e4e7ac8c021758b2bb28db60b3a787115f9114a6"
                           "41bf44f8ba99b.scope",
                 .expected_container_id = "9cc35a907a1e",
                 .should_match = true},

                // Rootless podman containers
                {.name = "rootless_user_slice_libpod_no_scope",
                 .cgroup = "/user.slice/user-1000.slice/user@1000.service/"
                           "libpod-"
                           "1234567890abcdef1234567890abcdef1234567890abcdef123"
                           "4567890abcdef",
                 .expected_container_id = "1234567890ab",
                 .should_match = true},

                // Containerd test cases
                {.name = "containerd_cgroupfs",
                 .cgroup = "/kubepods/besteffort/"
                           "podac04f3f2-1f2c-11e9-b015-1ebee232acfa/"
                           "605439acbd4fb18c145069289094b17f17e0cfa938f78012d49"
                           "60bc797305f22",
                 .expected_container_id = "605439acbd4f",
                 .should_match = true},
                {.name = "containerd_unknown",
                 .cgroup = "/kubepods-burstable-"
                           "podbd12dd3393227d950605a2444b13c27a.slice:cri-"
                           "containerd:"
                           "d52db56a9c80d536a91354c0951c061187ca46249e64865a127"
                           "03003d8f42366",
                 .expected_container_id = "d52db56a9c80",
                 .should_match = true},
                {.name = "containerd_default",
                 .cgroup = "/default/test_container",
                 .expected_container_id = "test_contain",
                 .should_match = true},
                {.name = "containerd_namespaced",
                 .cgroup = "/my_very_long_namespace-1.5/test_container",
                 .expected_container_id = "test_contain",
                 .should_match = true},

                // CRI-O test cases
                {.name = "crio_cgroupfs",
                 .cgroup = "/kubepods/besteffort/"
                           "pod63b3ebfc-2890-11e9-8154-16bf8ef8d9dc/"
                           "crio-"
                           "73bfe475650de66df8e2affdc98d440dcbe84f8df83b6f75a68"
                           "a82eb7026136a",
                 .expected_container_id = "73bfe475650d",
                 .should_match = true},
                {.name = "crio_systemd",
                 .cgroup = "/kubepods.slice/kubepods-besteffort.slice/"
                           "kubepods-besteffort-pod63b3ebfc_2890_11e9_8154_"
                           "16bf8ef8d9dc.slice/"
                           "crio-"
                           "17d8c9eacc629f9945f304d89e9708c0c619649a484a215b240"
                           "628319548a09f."
                           "scope",
                 .expected_container_id = "17d8c9eacc62",
                 .should_match = true},

                // Docker test cases
                {.name = "docker_cgroupfs",
                 .cgroup = "/docker/"
                           "7951fb549ab99e0722a949b6c121634e1f3a36b5bacbe539299"
                           "1e3b12251e6b8",
                 .expected_container_id = "7951fb549ab9",
                 .should_match = true},
                {.name = "docker_systemd",
                 .cgroup = "/docker.slice/"
                           "docker-"
                           "7951fb549ab99e0722a949b6c121634e1f3a36b5bacbe53"
                           "92991e3b12251e6b8.scope",
                 .expected_container_id = "7951fb549ab9",
                 .should_match = true},

                // Edge cases and failures
                {.name = "empty_cgroup", .cgroup = "/", .should_match = false},
                {.name = "container_id_too_long",
                 .cgroup = "/user.slice/user-1000.slice/user@1000.service/"
                           "libpod-"
                           "1234567890abcdef1234567890abcdef1234567890abcdef123"
                           "4567890abcdef1234567890abcde"
                           "f1234567890abcdef1234567890abcdef1234567890abcdef",
                 .should_match = false},
                {.name = "invalid_container_id_characters",
                 .cgroup = "/user.slice/user-1000.slice/user@1000.service/"
                           "libpod-"
                           "1234567890abcdef1234567890abcdef1234567890abcdef123"
                           "4567890abcdefg",
                 .should_match = false},
                {.name = "no_cgroups_at_all",
                 .cgroup = "/",
                 .should_match = false},
                {.name = "non_container_cgroup",
                 .cgroup = "/user.slice/user-1000.slice/user@1000.service/"
                           "init.scope",
                 .should_match = false}}),
        test_name_generator);
