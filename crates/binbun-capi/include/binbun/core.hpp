// binbun/core.hpp: what every part of the C++ wrapper shares, over
// binbun/core.h: the library's strings as std::string_view, statuses'
// names, the library's version. Included by each part's wrapper
// (binbun/disasm.hpp).
#ifndef BINBUN_CORE_HPP
#define BINBUN_CORE_HPP

#include <cstdint>
#include <string_view>

#include "core.h"

namespace binbun {

// A string of the library as a string_view.
inline std::string_view view(binbun_str s) noexcept { return {s.data, s.length}; }

// What a status means, in a few words.
inline std::string_view status_name(binbun_status status) noexcept { return view(binbun_status_name(status)); }

// The version of the library loaded.
inline std::uint32_t version() noexcept { return binbun_version(); }

}  // namespace binbun

#endif  // BINBUN_CORE_HPP
