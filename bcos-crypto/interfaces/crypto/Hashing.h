#pragma once
#include <bcos-utilities/FixedBytes.h>
#include <boost/range.hpp>
#include <boost/range/concepts.hpp>
#include <gsl/span>
#include <type_traits>

namespace bcos::crypto
{

// Hashing CRTP base
template <class Impl>
class Hashing
{
public:
    template <class POD>
    std::enable_if_t<std::is_trivial_v<POD>> update(const POD& pod)
    {
        auto buffer = (const byte*)&pod;
        auto length = sizeof(pod);

        update(gsl::span(buffer, length));
    }

    template <class Range>
    std::enable_if_t<std::is_class_v<Range>> update(const Range& range)
    {
        BOOST_CONCEPT_ASSERT((boost::RandomAccessRangeConcept<Range>));
        static_assert(std::is_trivial_v<typename boost::range_value<Range>::type>, "");

        auto buffer = (const byte*)&range[0];
        auto length = sizeof(boost::range_value<Range>) * boost::size(range);

        update(gsl::span(buffer, length));
    }

    template <class Input>
    auto& operator<<(Input&& input)
    {
        update(std::forward<Input>(input));
        return *this;
    }

    bcos::h256 operator()() { return final(); }

    void update(gsl::span<byte const> view) { impl().impl_update(view); }

    bcos::h256 final() { return impl().impl_final(); }

private:
    Impl& impl() { return *static_cast<Impl*>(this); }
};

}  // namespace bcos::crypto