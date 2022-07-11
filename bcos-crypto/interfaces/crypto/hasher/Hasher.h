/**
 *  Copyright (C) 2022 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @brief interface for Hasher
 * @file Hasher.h
 * @date 2022.05.30
 * @author ancelmo
 */

#pragma once
#include "../CommonType.h"

namespace bcos::crypto
{
// Hasher CRTP base
template <class Impl>
class HasherBase
{
public:
    HasherBase() = default;
    HasherBase(const HasherBase&) = default;
    HasherBase(HasherBase&&) = default;
    HasherBase& operator=(const HasherBase&) = default;
    HasherBase& operator=(HasherBase&&) = default;
    virtual ~HasherBase() = default;

    HashType calculate(bytesConstRef _input)
    {
        auto ctx = init();
        update(ctx, _input);
        return final(ctx);
    }

    void* update(void* _hashContext, bytesConstRef _input)
    {
        return impl().impl_update(_hashContext, _input);
    }

    void final(void* _hashContext, HashType& _output) { impl().impl_final(_hashContext, _output); }

    HashType final(void* hashContext)
    {
        HashType hashResult;
        final(hashContext, hashResult);
        return hashResult;
    }

    void* init() { return impl().init(); }

private:
    constexpr Impl& impl() { return *static_cast<Impl*>(this); }
};
}  // namespace bcos::crypto