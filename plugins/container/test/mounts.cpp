#include <gtest/gtest.h>
#include <container_info.h>

TEST(container_info, mounts)
{
    container_info info{};

    info.m_mounts.emplace_back("/tmp/foo", "/tmp/bar", "", false, "");

    EXPECT_NE(info.mount_by_source("foo"), nullptr);
    EXPECT_NE(info.mount_by_source("/tmp"), nullptr);
    EXPECT_NE(info.mount_by_source("/tmp/*"), nullptr);
    EXPECT_NE(info.mount_by_source("/tmp*"), nullptr);
    EXPECT_NE(info.mount_by_source("/"), nullptr);
    EXPECT_NE(info.mount_by_source("foo$"), nullptr);
    EXPECT_EQ(info.mount_by_source("^tmp"), nullptr);
    EXPECT_NE(info.mount_by_source("^/tmp"), nullptr);
    EXPECT_NE(info.mount_by_source("tmp/fo"), nullptr);
    EXPECT_NE(info.mount_by_source("tmp/[fo,ba]"), nullptr);
}