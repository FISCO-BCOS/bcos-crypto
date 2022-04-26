#pragma once
#include <bcos-utilities/FixedBytes.h>
#include <iterator>
#include <ranges>
#include <span>
#include <type_traits>

namespace bcos::crypto
{

// Hashing CRTP base
// Non thread-safe!
template <class Impl>
class HasherBase
{
public:
    // Accept POD or RandomAccessRange(with POD)
    auto& update(auto&& input)
    {
        using RawType = std::remove_cvref<decltype(input)>;
        if constexpr (std::is_trivial_v<RawType>)
        {
            impl().impl_update(std::span((const byte*)&input, sizeof(input)));
        }
        else if constexpr (std::ranges::contiguous_range<RawType> &&
                           std::is_trivial_v<std::ranges::range_value_t<RawType>>)
        {
            impl().impl_update(std::span((const byte*)std::data(input),
                sizeof(std::ranges::range_value_t<RawType>) * std::size(input)));
        }

        return *this;
    }

    bcos::h256 final() { return impl().impl_final(); }

private:
    Impl& impl() { return *static_cast<Impl*>(this); }
};

template <class Impl>
concept Hasher = std::is_base_of_v<HasherBase<Impl>, Impl>;

}  // namespace bcos::crypto