// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "xxhash_ext.h"

#include <iostream>
#include <cstdint>
#include <cmath>
#include <vector>
#include <algorithm>

/*
CountMinSketch Powered Probabilistic Counting and Filtering
Falco Proposal: https://github.com/falcosecurity/falco/blob/master/proposals/20230620-anomaly-detection-framework.md
*/

namespace plugin::anomalydetection::num
{

template<typename T>
class cms 
{
private:
    std::unique_ptr<std::unique_ptr<T[]>[]> sketch;
    uint64_t d_; // d / Rows / number of hash functions
    uint64_t w_; // w / Cols / number of buckets
    double gamma_; // Error probability (e.g. 0.001)
    double eps_; // Relative error (e.g. 0.0001)

public:
    cms(double gamma, double eps) 
    {
        d_ = static_cast<uint64_t>(std::ceil(std::log(1.0 / gamma))); // -> determine Rows / number of hash functions
        w_ = static_cast<uint64_t>(std::ceil(std::exp(1) / eps)); // -> determine Cols / number of buckets
        gamma_ = gamma;
        eps_ = eps;
        sketch = std::make_unique<std::unique_ptr<T[]>[]>(d_);
        for (uint64_t i = 0; i < d_; ++i) 
        {
            sketch[i] = std::make_unique<T[]>(w_);
            std::fill(sketch[i].get(), sketch[i].get() + w_, static_cast<T>(0)); // Init to 0
        }
    }

    // Overloaded constructor
    cms(uint64_t d, uint64_t w)
    {
        d_ = d;
        w_ = w;
        gamma_ = 1.0 / std::exp(d); // -> reverse calculate error probability from Rows / number of hash functions 
        eps_ = std::exp(1) / w; // -> reverse calculate relative error from Cols / number of buckets
        sketch = std::make_unique<std::unique_ptr<T[]>[]>(d_);
        for (uint64_t i = 0; i < d_; ++i) 
        {
            sketch[i] = std::make_unique<T[]>(w_);
            std::fill(sketch[i].get(), sketch[i].get() + w_, static_cast<T>(0)); // Init to 0
        }
    }

    uint64_t hash_XXH3_seed(std::string value, uint64_t seed) const
    {
        // using https://raw.githubusercontent.com/Cyan4973/xxHash/v0.8.2/xxhash.h
        // Requirement: Need fast and reliable independent hash functions.
        uint64_t hash = XXH3_64bits_withSeed(value.c_str(), value.size(), seed);
        return hash;
    }

    void update(std::string value, T count)
    {
        // Update counts for each hash function.
        // Note: d is typically very small (e.g. < 10)
        for (uint64_t seed = 0; seed < d_; ++seed)
        {
            // Map the hash value to an index of the current sketch Row by taking the modulo of the hash value, where w is the number of buckets.
            // Simply loop over d, which is the number of hash functions, to obtain a seed in order to use independent hash functions for each Row.
            sketch[seed][hash_XXH3_seed(value, seed) % w_] += count;
        }
    }

    T update_estimate(std::string value, T count) const
    {
        std::vector<T> estimates;
        // Same as the update function, but also returns the minimum count as an estimate.
        // Note: d is typically very small (e.g. < 10)
        for (uint64_t seed = 0; seed < d_; ++seed)
        {
            T index = hash_XXH3_seed(value, seed) % w_;
            sketch[seed][index] += count;
            estimates.push_back(sketch[seed][index]);
        }
        auto min_element = std::min_element(estimates.begin(), estimates.end());
        return min_element != estimates.end() ? *min_element : T();
    }

    T estimate(std::string value) const
    {
        std::vector<T> estimates;
        // Return the minimum count across hash functions as an estimate.
        // Note: d is typically very small (e.g. < 10)
        for (uint64_t seed = 0; seed < d_; ++seed)
        {
            T index = hash_XXH3_seed(value, seed) % w_;
            estimates.push_back(sketch[seed][index]);
        }
        auto min_element = std::min_element(estimates.begin(), estimates.end());
        return min_element != estimates.end() ? *min_element : T();
    }

    T get_item(uint64_t row, uint64_t col) const
    {
        if (row >= 0 && row < d_ && col >= 0 && col < w_) 
        {
            return sketch[row][col];
        } else
        {
            return T();
        }
    }

    size_t get_size_bytes() const 
    {
        return d_ * w_ * sizeof(T);
    }

    std::pair<uint64_t, uint64_t> get_dimensions() const
    {
        return std::make_pair(d_, w_);
    }

    // Return Rows / number of hash functions 
    uint64_t get_d() const
    {
        return d_;
    }

    // Return Cols / number of buckets
    uint64_t get_w() const
    {
        return w_;
    }

    // Return error probability
    double get_gamma() const
    {
        return gamma_;
    }

    // Return relative error
    double get_eps() const
    {
        return eps_;
    }

    cms(cms&&) noexcept = default;
	cms(const cms&) = default;
	cms& operator=(cms&&) noexcept = default;
	cms& operator=(const cms&) = default;
	cms() = delete;
};

} // namespace plugin::anomalydetection::num
