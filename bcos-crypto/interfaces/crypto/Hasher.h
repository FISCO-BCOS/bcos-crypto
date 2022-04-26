#pragma once
#include <bcos-utilities/FixedBytes.h>
#include <boost/throw_exception.hpp>
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
    // Accept POD
    auto& update(auto&& input)
    {
        using Type = typename std::remove_cvref<decltype(input)>::type;
        if constexpr (std::is_trivial_v<Type>)
        {
            impl().impl_update(std::span((const byte*)&input, sizeof(input)));
        }
        else if constexpr (std::ranges::contiguous_range<Type> &&
                           std::is_trivial_v<std::ranges::range_value_t<Type>>)
        {
            impl().impl_update(std::span((const byte*)std::data(input),
                sizeof(std::ranges::range_value_t<Type>) * std::size(input)));
        }
        else
        {
            static_assert(!sizeof(Type), "No match type! Input type must be POD or range of POD");
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