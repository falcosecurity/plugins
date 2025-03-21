#pragma once

#include <string>
#include <vector>

namespace libsinsp
{
namespace runc
{

/**
 * @brief A pattern to match cgroup paths against
 *
 *  runc-based runtimes (Docker, containerd, CRI-O, probably others) use the
 * same two cgroup layouts with slight variations:
 *  - non-systemd layout uses cgroups ending with .../<prefix><container id>
 *  - systemd layout uses .../<prefix><container id>.scope
 *  where <container id> is always 64 hex digits (we report the first 12 as the
 * container id). For non-systemd only CRI-O seems to use /crio-<container id>,
 * while for systemd layout while all known container engines use a prefix like
 * "docker-", "crio-" or "containerd-cri-". We can encode all these variants
 * with a simple list of (prefix, suffix) pairs (the last one must be a pair of
 * null pointers to mark the end of the array)
 */
struct cgroup_layout
{
    const char *prefix;
    const char *suffix;
};

/**
 * @brief Check if `cgroup` ends with <prefix><64_hex_digits><suffix>
 * @param container_id output parameter
 * @return true if `cgroup` matches the pattern
 *
 * If this function returns true, `container_id` will be set to
 * the truncated hex string (first 12 digits). Otherwise, it will remain
 * unchanged.
 */
bool match_one_container_id(const std::string &cgroup,
                            const std::string &prefix,
                            const std::string &suffix,
                            std::string &container_id);

/**
 * @brief Match `cgroup` against a list of layouts using
 * `match_one_container_id()`
 * @param layout an array of (prefix, suffix) pairs
 * @param container_id output parameter
 * @return true if `cgroup` matches any of the patterns
 *
 * `layout` is an array terminated by an empty entry (prefix, suffix both empty)
 *
 * If this function returns true, `container_id` will be set to
 * the truncated hex string (first 12 digits). Otherwise, it will remain
 * unchanged.
 */
bool matches_runc_cgroup(const std::string &cgroup,
                         const libsinsp::runc::cgroup_layout *layout,
                         std::string &container_id, bool is_containerd = false);
} // namespace runc
} // namespace libsinsp
