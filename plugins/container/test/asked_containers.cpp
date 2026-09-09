#include <gtest/gtest.h>
#include <asked_containers.h>

using namespace std::chrono_literals;

namespace
{
const auto t0 = asked_containers::clock::time_point(1h);
}

TEST(asked_containers, pending_until_ttl)
{
    asked_containers asked(10s);
    EXPECT_FALSE(asked.pending("abc", t0));

    asked.add("abc", t0);
    EXPECT_TRUE(asked.pending("abc", t0));
    EXPECT_TRUE(asked.pending("abc", t0 + 9s));
    EXPECT_EQ(asked.size(), 1u);

    // Expired: dropped, and can be asked again
    EXPECT_FALSE(asked.pending("abc", t0 + 10s));
    EXPECT_EQ(asked.size(), 0u);
    asked.add("abc", t0 + 10s);
    EXPECT_TRUE(asked.pending("abc", t0 + 19s));
    EXPECT_FALSE(asked.pending("abc", t0 + 20s));
}

TEST(asked_containers, erase)
{
    asked_containers asked(10s);
    asked.add("abc", t0);
    asked.erase("abc");
    EXPECT_FALSE(asked.pending("abc", t0));
    EXPECT_EQ(asked.size(), 0u);
    // Unknown containers are fine
    asked.erase("def");
    EXPECT_EQ(asked.size(), 0u);
}

TEST(asked_containers, add_purges_expired_entries)
{
    asked_containers asked(10s);
    for(int i = 0; i < 100; i++)
    {
        asked.add(std::to_string(i), t0);
    }
    EXPECT_EQ(asked.size(), 100u);

    // Nothing has expired yet
    asked.add("a", t0 + 5s);
    EXPECT_EQ(asked.size(), 101u);

    // Two expired entries go per insertion
    asked.add("b", t0 + 10s);
    EXPECT_EQ(asked.size(), 100u);
    asked.add("c", t0 + 10s);
    EXPECT_EQ(asked.size(), 99u);

    // The entries that did not expire are untouched
    EXPECT_TRUE(asked.pending("a", t0 + 10s));
    EXPECT_TRUE(asked.pending("b", t0 + 10s));
    EXPECT_TRUE(asked.pending("c", t0 + 10s));
    EXPECT_TRUE(asked.pending("99", t0 + 9s));
}

TEST(asked_containers, purge_skips_entries_asked_again)
{
    asked_containers asked(10s);
    asked.add("x", t0);
    asked.add("x", t0 + 1s);
    EXPECT_EQ(asked.size(), 1u);

    // The stale record of the first insertion is skipped, the entry stays
    asked.add("y", t0 + 10s);
    EXPECT_EQ(asked.size(), 2u);
    EXPECT_TRUE(asked.pending("x", t0 + 10s));
    EXPECT_FALSE(asked.pending("x", t0 + 11s));

    // The stale record of an erased entry is skipped as well
    asked.add("z", t0 + 11s);
    asked.erase("z");
    asked.add("w", t0 + 21s);
    EXPECT_EQ(asked.size(), 1u);
    EXPECT_TRUE(asked.pending("w", t0 + 21s));
}
