#pragma once
#include <bcos-utilities/FixedBytes.h>
#include <boost/range.hpp>
#include <boost/range/concepts.hpp>
#include <gsl/span>
#include <type_traits>

namespace bcos::crypto
{

// Hashing CRTP base
// Non thread-safe!
template <class Impl>
class Hashing
{
public:
    // Accept POD or RandomAccessRange(with POD)
    template <class Input>
    auto& update(Input&& input)
    {
        using RawType = typename std::remove_cv_t<typename std::remove_reference_t<Input>>;
        if constexpr (std::is_trivial_v<RawType>)
        {
            update(gsl::span((const byte*)&input, sizeof(input)));
        }
        else
        {
            BOOST_CONCEPT_ASSERT((boost::RandomAccessRangeConcept<RawType>));
            static_assert(std::is_trivial_v<typename boost::range_value<RawType>::type>,
                "Range contains non trivial type is not allow!");

            update(gsl::span(
                (const byte*)&input[0], sizeof(boost::range_value<Input>) * boost::size(input)));
        }
        return *this;
    }

    template <class Input>
    auto& operator<<(Input&& input)
    {
        return update(std::forward<Input>(input));
    }

    bcos::h256 operator()() { return final(); }

    void update(gsl::span<byte const> view) { impl().impl_update(view); }

    bcos::h256 final() { return impl().impl_final(); }

private:
    Impl& impl() { return *static_cast<Impl*>(this); }
};

}  // namespace bcos::crypto