#include <gtest/gtest.h>
#include <utils.h>
#include <memory>
#include <string>

// Test basic set and get operations
TEST(LRU, BasicSetGet)
{
    LRU<int, std::string> cache(3);

    std::string value;
    EXPECT_FALSE(cache.get(1, value)); // Not in cache yet

    cache.set(1, "one");
    EXPECT_TRUE(cache.get(1, value));
    EXPECT_EQ(value, "one");

    cache.set(2, "two");
    EXPECT_TRUE(cache.get(2, value));
    EXPECT_EQ(value, "two");

    // First key should still be accessible
    EXPECT_TRUE(cache.get(1, value));
    EXPECT_EQ(value, "one");
}

// Test cache capacity and eviction
TEST(LRU, CapacityEviction)
{
    LRU<int, std::string> cache(2);

    cache.set(1, "one");
    cache.set(2, "two");

    std::string value;
    EXPECT_TRUE(cache.get(1, value));
    EXPECT_TRUE(cache.get(2, value));

    // Adding third element should evict the least recently used (1)
    cache.set(3, "three");

    EXPECT_FALSE(cache.get(1, value)); // Should be evicted
    EXPECT_TRUE(cache.get(2, value));  // Should still be present
    EXPECT_EQ(value, "two");
    EXPECT_TRUE(cache.get(3, value)); // Should be present
    EXPECT_EQ(value, "three");
}

// Test LRU ordering - accessing an element makes it most recently used
TEST(LRU, LRUOrdering)
{
    LRU<int, std::string> cache(2);

    cache.set(1, "one");
    cache.set(2, "two");

    std::string value;
    // Access key 1 to make it most recently used
    EXPECT_TRUE(cache.get(1, value));
    EXPECT_EQ(value, "one");

    // Add new element - should evict key 2 (least recently used)
    cache.set(3, "three");

    EXPECT_TRUE(cache.get(1, value)); // Should still be present
    EXPECT_EQ(value, "one");
    EXPECT_FALSE(cache.get(2, value)); // Should be evicted
    EXPECT_TRUE(cache.get(3, value));  // Should be present
    EXPECT_EQ(value, "three");
}

// Test updating existing keys
TEST(LRU, UpdateExisting)
{
    LRU<int, std::string> cache(2);

    cache.set(1, "one");
    cache.set(2, "two");

    // Update key 1
    cache.set(1, "ONE");

    std::string value;
    EXPECT_TRUE(cache.get(1, value));
    EXPECT_EQ(value, "ONE"); // Should have updated value

    // Key 1 should now be most recently used
    cache.set(3, "three");

    EXPECT_TRUE(cache.get(1, value));  // Should still be present
    EXPECT_FALSE(cache.get(2, value)); // Should be evicted (was LRU)
    EXPECT_TRUE(cache.get(3, value));  // Should be present
}

// Test with complex value types (pair of string and shared_ptr)
TEST(LRU, ComplexValueType)
{
    using ValueType = std::pair<std::string, std::shared_ptr<int>>;
    LRU<std::string, ValueType> cache(2);

    auto ptr1 = std::make_shared<int>(42);
    auto ptr2 = std::make_shared<int>(100);

    cache.set("key1", {"container1", ptr1});
    cache.set("key2", {"container2", ptr2});

    ValueType value;
    EXPECT_TRUE(cache.get("key1", value));
    EXPECT_EQ(value.first, "container1");
    EXPECT_EQ(*value.second, 42);
    EXPECT_EQ(ptr1.use_count(), 3); // ptr1, cache, and value

    EXPECT_TRUE(cache.get("key2", value));
    EXPECT_EQ(value.first, "container2");
    EXPECT_EQ(*value.second, 100);
}

// Test cache with capacity 1
TEST(LRU, SingleCapacity)
{
    LRU<int, std::string> cache(1);

    cache.set(1, "one");

    std::string value;
    EXPECT_TRUE(cache.get(1, value));
    EXPECT_EQ(value, "one");

    // Adding second element should evict the first
    cache.set(2, "two");
    EXPECT_FALSE(cache.get(1, value));
    EXPECT_TRUE(cache.get(2, value));
    EXPECT_EQ(value, "two");
}

// Test repeated updates don't break cache
TEST(LRU, RepeatedUpdates)
{
    LRU<int, std::string> cache(2);

    cache.set(1, "one");
    cache.set(1, "ONE");
    cache.set(1, "uno");

    std::string value;
    EXPECT_TRUE(cache.get(1, value));
    EXPECT_EQ(value, "uno");

    cache.set(2, "two");
    EXPECT_TRUE(cache.get(1, value));
    EXPECT_EQ(value, "uno");
    EXPECT_TRUE(cache.get(2, value));
    EXPECT_EQ(value, "two");

    cache.set(3, "three");

    value = "";
    EXPECT_FALSE(cache.get(1, value));
    EXPECT_EQ(value, "");
}

// Test with string keys (as used in container matcher)
TEST(LRU, StringKeys)
{
    LRU<std::string, std::string> cache(3);

    cache.set("/kubepods/pod123", "container123");
    cache.set("/docker/abc456", "containerabc");
    cache.set("/libpod-def789", "containerdef");

    std::string value;
    EXPECT_TRUE(cache.get("/kubepods/pod123", value));
    EXPECT_EQ(value, "container123");
    EXPECT_TRUE(cache.get("/docker/abc456", value));
    EXPECT_EQ(value, "containerabc");
    EXPECT_TRUE(cache.get("/libpod-def789", value));
    EXPECT_EQ(value, "containerdef");

    // Access middle key
    EXPECT_TRUE(cache.get("/docker/abc456", value));

    // Add fourth element - should evict first one
    cache.set("/crio-xyz", "containerxyz");

    EXPECT_FALSE(cache.get("/kubepods/pod123", value)); // Evicted
    EXPECT_TRUE(cache.get("/docker/abc456", value));    // Still present
    EXPECT_TRUE(cache.get("/libpod-def789", value));    // Still present
    EXPECT_TRUE(cache.get("/crio-xyz", value));         // New entry
}

// Test cache behavior with default capacity
TEST(LRU, DefaultCapacity)
{
    LRU<int, std::string> cache; // Uses default capacity (100)

    // Add many elements
    for(int i = 0; i < 100; i++)
    {
        cache.set(i, "value" + std::to_string(i));
    }

    std::string value;
    // All 100 should be present
    for(int i = 0; i < 100; i++)
    {
        EXPECT_TRUE(cache.get(i, value));
    }

    // Adding 101st element should evict the first one
    cache.set(100, "value100");
    EXPECT_FALSE(cache.get(0, value));  // Should be evicted
    EXPECT_TRUE(cache.get(100, value)); // Should be present
    EXPECT_TRUE(cache.get(99, value));  // Should still be present
}

// Test with nullptr values (as used in matcher for host cgroups)
TEST(LRU, NullptrValues)
{
    using ValueType = std::pair<std::string, std::shared_ptr<int>>;
    LRU<std::string, ValueType> cache(2);

    // Simulate host cgroup (empty string, nullptr)
    cache.set("/host/cgroup", {"", nullptr});
    cache.set("/container/cgroup", {"container123", std::make_shared<int>(42)});

    ValueType value;
    EXPECT_TRUE(cache.get("/host/cgroup", value));
    EXPECT_EQ(value.first, "");
    EXPECT_EQ(value.second, nullptr);

    EXPECT_TRUE(cache.get("/container/cgroup", value));
    EXPECT_EQ(value.first, "container123");
    EXPECT_NE(value.second, nullptr);
}
