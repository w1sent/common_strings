// C++ program to extract printable strings (ASCII, UTF-8, UTF-16) from files,
// group them by top-level entry (files individually; first-level subfolders merged recursively),
// compute the intersection across all groups, and print / optionally write to a file.
// Also supports optional substring intersection via k-grams with maximal-materialization.
//
#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif
#include <optional>
#include <print>
#include <map>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using namespace std::literals;

// ---------- ANSI color helpers ----------
namespace ansi
{
    constexpr std::string_view reset = "\033[0m";
    constexpr std::string_view green = "\033[32m";
    constexpr std::string_view yellow = "\033[33m";
    constexpr std::string_view red = "\033[31m";
    constexpr std::string_view blue = "\033[34m";
    constexpr std::string_view magenta = "\033[35m";
}

enum class LogLevel { info, warn, error, debug };

static bool g_debug = false; // toggled by -v/--verbose

template <class... Ts>
void log(LogLevel lvl, std::format_string<Ts...> fmt, Ts&&... args)
{
    auto tag = [lvl]
    {
        switch (lvl)
        {
        case LogLevel::info: return "INFO"sv;
        case LogLevel::warn: return "WARN"sv;
        case LogLevel::error: return "ERR "sv;
        case LogLevel::debug: return "DBG "sv;
        }
        return "INFO"sv;
    }();
    auto color = [lvl]
    {
        switch (lvl)
        {
        case LogLevel::info: return ansi::green;
        case LogLevel::warn: return ansi::yellow;
        case LogLevel::error: return ansi::red;
        case LogLevel::debug: return ansi::magenta;
        }
        return ansi::green;
    }();
    if (lvl == LogLevel::debug && !g_debug) return;
    auto msg = std::format(fmt, std::forward<Ts>(args)...);
    std::println("{}[{}] {}{}", color, tag, msg, ansi::reset);
}

// ---------- CLI parsing ----------
struct Options
{
    fs::path root;
    std::optional<fs::path> output;
    std::size_t min_len = 4; // minimum length in characters (code points for UTF-8/16)
    bool skip_utf8 = false;
    bool skip_utf16 = true;
    bool include_hidden = false; // off by default
    bool show_locations = false; // list locations of results
    bool show_types = false; // show encoding type(s)
    bool ignore_case = false; // ASCII-only case-insensitive matching
    std::optional<fs::path> ignorelist_path; // optional ignore list file

    enum class Utf16Mode { auto_bom, le, be, both } utf16_mode = Utf16Mode::both;

    bool substr_mode = false; // off by default
    std::size_t gram_len = 0; // defaults to min_len if 0
    bool strict_groups = false; // include empty groups
    bool verbose = false; // -v / --verbose
    bool help = false;
};

static void print_help()
{
    std::print(
        R"(common_strings - Extract strings from files and print the intersection across groups

USAGE:
  common_strings <folder> [options]

Groups:
  - Each top-level FILE under <folder> forms its own group.
  - Each first-level SUBFOLDER is scanned recursively; all its files merge into one group.
  - The final output is the intersection of all groups' string sets.

Options:
  -m, --min-len <N>       Minimum string length to include (default: 4)
      --skip-utf8         Skip scanning for UTF-8 strings
      --skip-utf16        Skip scanning for UTF-16 strings (default)
      --utf16             Enable scanning for UTF-16 strings
      --utf16-endian <MODE>
                          One of: auto | le | be | both (default: both)
      --include-hidden    Include hidden entries (dotfiles, Windows hidden)
      --show-locations    Show locations as path:start:end (byte offsets)
      --show-types        Show encoding type(s) for matches
  -i, --ignore-case       Case-insensitive matching (ASCII fold)
      --ignorelist <file> Exclude strings listed in file (one per line; '#' comments)
      --substr            Enable substring intersection (k-grams)
      --gram-len <K>      K for k-grams (default: --min-len)
      --strict-groups     Do NOT drop empty groups (intersection may be empty)
  -o, --output <file>     Write intersection to file (one per line)
  -v, --verbose           Verbose logging (enables debug lines)
  -h, --help              Show this help and exit

Notes:
  * ASCII scanning is always enabled.
  * UTF-16 endianness: 'auto' honors a BOM if present; 'both' scans as LE and BE.
  * Substring mode finds substrings of length >= K common to all groups, and materializes maximal ones.
)"
    );
}

static std::optional<std::size_t> parse_size(const std::string_view sv)
{
    std::size_t v{};
    auto* first = sv.data();
    auto* last = sv.data() + sv.size();
    if (auto [ptr, ec] = std::from_chars(first, last, v); ec == std::errc() && ptr == last) return v;
    return std::nullopt;
}

static std::optional<Options> parse_args(const int argc, char** argv)
{
    if (argc <= 1)
    {
        print_help();
        return std::nullopt;
    }
    Options opt{};
    std::vector<std::string_view> args(argv + 1, argv + argc);

    bool folder_set = false;
    for (const auto a : args)
    {
        if (a == "-h" || a == "--help")
        {
            opt.help = true;
            return opt;
        }
    }

    for (std::size_t i = 0; i < args.size(); ++i)
    {
        auto a = args[i];
        if (!a.empty() && a[0] != '-')
        {
            if (!folder_set)
            {
                opt.root = fs::path(std::string(a));
                folder_set = true;
                continue;
            }
        }
        if (a == "-m"sv || a == "--min-len"sv)
        {
            if (i + 1 >= args.size())
            {
                log(LogLevel::error, "Missing value for {}", a);
                return std::nullopt;
            }
            auto val = parse_size(args[++i]);
            if (!val)
            {
                log(LogLevel::error, "Invalid number for --min-len: {}", args[i]);
                return std::nullopt;
            }
            opt.min_len = *val;
        }
        else if (a == "--skip-utf8"sv)
        {
            opt.skip_utf8 = true;
        }
        else if (a == "--skip-utf16"sv)
        {
            opt.skip_utf16 = true;
        }
        else if (a == "--utf16"sv)
        {
            opt.skip_utf16 = false;
        }
        else if (a == "--include-hidden"sv)
        {
            opt.include_hidden = true;
        }
        else if (a == "--show-locations"sv)
        {
            opt.show_locations = true;
        }
        else if (a == "--show-types"sv)
        {
            opt.show_types = true;
        }
        else if (a == "-i"sv || a == "--ignore-case"sv)
        {
            opt.ignore_case = true;
        }
        else if (a == "--ignorelist"sv)
        {
            if (i + 1 >= args.size())
            {
                log(LogLevel::error, "Missing value for --ignorelist");
                return std::nullopt;
            }
            opt.ignorelist_path = fs::path(std::string(args[++i]));
        }
        else if (a == "--utf16-endian"sv)
        {
            if (i + 1 >= args.size())
            {
                log(LogLevel::error, "Missing value for --utf16-endian");
                return std::nullopt;
            }
            if (auto v = args[++i]; v == "auto"sv) opt.utf16_mode = Options::Utf16Mode::auto_bom;
            else if (v == "le"sv) opt.utf16_mode = Options::Utf16Mode::le;
            else if (v == "be"sv) opt.utf16_mode = Options::Utf16Mode::be;
            else if (v == "both"sv) opt.utf16_mode = Options::Utf16Mode::both;
            else
            {
                log(LogLevel::error, "Invalid --utf16-endian: {} (use auto|le|be|both)", v);
                return std::nullopt;
            }
        }
        else if (a == "--substr"sv)
        {
            opt.substr_mode = true;
        }
        else if (a == "--gram-len"sv)
        {
            if (i + 1 >= args.size())
            {
                log(LogLevel::error, "Missing value for --gram-len");
                return std::nullopt;
            }
            auto val = parse_size(args[++i]);
            if (!val)
            {
                log(LogLevel::error, "Invalid number for --gram-len: {}", args[i]);
                return std::nullopt;
            }
            opt.gram_len = *val;
        }
        else if (a == "--strict-groups"sv)
        {
            opt.strict_groups = true;
        }
        else if (a == "-o"sv || a == "--output"sv)
        {
            if (i + 1 >= args.size())
            {
                log(LogLevel::error, "Missing value for {}", a);
                return std::nullopt;
            }
            opt.output = fs::path(std::string(args[++i]));
        }
        else if (a == "-v"sv || a == "--verbose"sv)
        {
            opt.verbose = true;
        }
        else if (a == "-h"sv || a == "--help"sv)
        {
            opt.help = true;
            return opt;
        }
        else if (!a.empty() && a[0] == '-')
        {
            log(LogLevel::warn, "Unknown option: {}", a);
            return std::nullopt;
        }
    }
    if (!folder_set)
    {
        log(LogLevel::error, "Missing <folder> positional argument");
        return std::nullopt;
    }
    if (opt.gram_len == 0) opt.gram_len = opt.min_len;
    if (opt.gram_len == 0) opt.gram_len = 1; // safety
    return opt;
}

// ---------- File reading ----------
static std::vector<std::uint8_t> read_file_bytes(const fs::path& p)
{
    std::ifstream ifs(p, std::ios::binary);
    if (!ifs) return {};
    ifs.seekg(0, std::ios::end);
    const auto sz = static_cast<std::size_t>(ifs.tellg());
    ifs.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(sz);
    if (sz) ifs.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(sz));
    return data;
}

// ---------- UTF helpers ----------
static inline bool is_printable_ascii(std::uint8_t b) { return b >= 0x20 && b <= 0x7E; }

static inline bool is_printable_codepoint(char32_t cp)
{
    if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) return false;
    if (cp > 0x10FFFF) return false;
    if (cp >= 0xD800 && cp <= 0xDFFF) return false; // surrogate range
    if ((cp & 0xFFFE) == 0xFFFE) return false; // U+FFFE, U+FFFF, etc.
    if (cp >= 0xFDD0 && cp <= 0xFDEF) return false; // noncharacters
    // allow SPACE but reject common line breaks
    if (cp == U'\n' || cp == U'\r' || cp == U'\t') return false;
    return true;
}

static inline std::uint8_t to_lower_ascii(std::uint8_t b)
{
    if (b >= 'A' && b <= 'Z') return static_cast<std::uint8_t>(b + 32);
    return b;
}

static std::string to_lower_ascii_str(std::string s)
{
    for (auto& ch : s)
    {
        auto b = static_cast<std::uint8_t>(ch);
        if (b >= 'A' && b <= 'Z') ch = static_cast<char>(b + 32);
    }
    return s;
}

static inline void append_utf8(std::string& out, const char32_t cp)
{
    if (cp <= 0x7F) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7FF)
    {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    else if (cp <= 0xFFFF)
    {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    else
    {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

static inline bool is_cont_byte(const std::uint8_t b) { return (b & 0xC0) == 0x80; }

static std::optional<std::pair<char32_t, std::size_t>> decode_utf8(const std::uint8_t* s, std::size_t n)
{
    if (n == 0) return std::nullopt;
    std::uint8_t b0 = s[0];
    if (b0 <= 0x7F) return {{b0, 1}};
    if (b0 >= 0xC2 && b0 <= 0xDF)
    {
        if (n < 2 || !is_cont_byte(s[1])) return std::nullopt;
        char32_t cp = ((b0 & 0x1F) << 6) | (s[1] & 0x3F);
        return {{cp, 2}};
    }
    if (b0 == 0xE0)
    {
        if (n < 3 || !(s[1] >= 0xA0 && s[1] <= 0xBF) || !is_cont_byte(s[2])) return std::nullopt;
        char32_t cp = ((b0 & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return {{cp, 3}};
    }
    if (b0 >= 0xE1 && b0 <= 0xEC)
    {
        if (n < 3 || !is_cont_byte(s[1]) || !is_cont_byte(s[2])) return std::nullopt;
        char32_t cp = ((b0 & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return {{cp, 3}};
    }
    if (b0 == 0xED)
    {
        if (n < 3 || !(s[1] >= 0x80 && s[1] <= 0x9F) || !is_cont_byte(s[2])) return std::nullopt;
        char32_t cp = ((b0 & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return {{cp, 3}};
    }
    if (b0 >= 0xEE && b0 <= 0xEF)
    {
        if (n < 3 || !is_cont_byte(s[1]) || !is_cont_byte(s[2])) return std::nullopt;
        char32_t cp = ((b0 & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return {{cp, 3}};
    }
    if (b0 == 0xF0)
    {
        if (n < 4 || !(s[1] >= 0x90 && s[1] <= 0xBF) || !is_cont_byte(s[2]) || !is_cont_byte(s[3])) return std::nullopt;
        char32_t cp = ((b0 & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return {{cp, 4}};
    }
    if (b0 >= 0xF1 && b0 <= 0xF3)
    {
        if (n < 4 || !is_cont_byte(s[1]) || !is_cont_byte(s[2]) || !is_cont_byte(s[3])) return std::nullopt;
        char32_t cp = ((b0 & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return {{cp, 4}};
    }
    if (b0 == 0xF4)
    {
        if (n < 4 || !(s[1] >= 0x80 && s[1] <= 0x8F) || !is_cont_byte(s[2]) || !is_cont_byte(s[3])) return std::nullopt;
        char32_t cp = ((b0 & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return {{cp, 4}};
    }
    return std::nullopt;
}

// ---------- Extractors ----------
struct ExtractOptions
{
    std::size_t min_len;
    bool do_utf8;
    bool do_utf16;
    Options::Utf16Mode utf16_mode;
};

static void extract_ascii(const std::vector<std::uint8_t>& data, const ExtractOptions& eopt,
                          std::unordered_set<std::string>& out)
{
    std::size_t i = 0;
    const std::size_t n = data.size();
    while (i < n)
    {
        while (i < n && !is_printable_ascii(data[i])) ++i;
        const auto start = i;
        while (i < n && is_printable_ascii(data[i])) ++i;
        if (i > start && (i - start) >= eopt.min_len)
            out.emplace(reinterpret_cast<const char*>(data.data() + start),
                        i - start);
    }
}

static void extract_utf8(const std::vector<std::uint8_t>& data, const ExtractOptions& eopt,
                         std::unordered_set<std::string>& out)
{
    std::size_t i = 0;
    const std::size_t n = data.size();
    std::string current;
    std::size_t cp_count = 0;
    auto flush = [&]
    {
        if (cp_count >= eopt.min_len) out.emplace(current);
        current.clear();
        cp_count = 0;
    };
    while (i < n)
    {
        auto dec = decode_utf8(data.data() + i, n - i);
        if (!dec)
        {
            flush();
            ++i;
            continue;
        }
        auto [cp, len] = *dec;
        if (!is_printable_codepoint(cp))
        {
            flush();
            i += len;
            continue;
        }
        current.append(reinterpret_cast<const char*>(data.data() + i), len);
        ++cp_count;
        i += len;
    }
    flush();
}

enum class Endian { LE, BE };

static std::optional<Endian> bom_to_endian(const std::vector<std::uint8_t>& data)
{
    if (data.size() >= 2)
    {
        if (data[0] == 0xFF && data[1] == 0xFE) return Endian::LE;
        if (data[0] == 0xFE && data[1] == 0xFF) return Endian::BE;
    }
    return std::nullopt;
}

static inline std::uint16_t load16(const std::uint8_t* p, const Endian e)
{
    return (e == Endian::LE)
               ? (static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8))
               : (static_cast<std::uint16_t>(p[1]) | (static_cast<std::uint16_t>(p[0]) << 8));
}

static void extract_utf16_pass(const std::vector<std::uint8_t>& data, const Endian e, const ExtractOptions& eopt,
                               std::unordered_set<std::string>& out)
{
    if (data.size() < 2) return;
    std::size_t i = 0;
    const std::size_t n = data.size();
    std::string current;
    std::size_t cp_count = 0;
    auto flush = [&]
    {
        if (cp_count >= eopt.min_len) out.emplace(current);
        current.clear();
        cp_count = 0;
    };
    while (i + 1 < n)
    {
        const std::uint16_t u = load16(&data[i], e);
        i += 2;
        if (u == 0xFEFF)
        {
            flush();
            continue;
        }
        char32_t cp = 0;
        if (u >= 0xD800 && u <= 0xDBFF)
        {
            if (i + 1 >= n)
            {
                flush();
                break;
            }
            if (const std::uint16_t u2 = load16(&data[i], e); u2 >= 0xDC00 && u2 <= 0xDFFF)
            {
                i += 2;
                cp = 0x10000 + (((u - 0xD800) << 10) | (u2 - 0xDC00));
            }
            else
            {
                flush();
                continue;
            }
        }
        else if (u >= 0xDC00 && u <= 0xDFFF)
        {
            flush();
            continue;
        }
        else { cp = u; }
        if (!is_printable_codepoint(cp))
        {
            flush();
            continue;
        }
        append_utf8(current, cp);
        ++cp_count;
    }
    flush();
}

static void extract_utf16(const std::vector<std::uint8_t>& data, const ExtractOptions& eopt,
                          std::unordered_set<std::string>& out)
{
    if (data.size() < 2) return;
    const auto bom = bom_to_endian(data);
    switch (eopt.utf16_mode)
    {
    case Options::Utf16Mode::auto_bom:
        if (bom) extract_utf16_pass(data, *bom, eopt, out);
        else
        {
            extract_utf16_pass(data, Endian::LE, eopt, out);
            extract_utf16_pass(data, Endian::BE, eopt, out);
        }
        break;
    case Options::Utf16Mode::le: extract_utf16_pass(data, Endian::LE, eopt, out);
        break;
    case Options::Utf16Mode::be: extract_utf16_pass(data, Endian::BE, eopt, out);
        break;
    case Options::Utf16Mode::both: extract_utf16_pass(data, Endian::LE, eopt, out);
        extract_utf16_pass(data, Endian::BE, eopt, out);
        break;
    }
}

static std::unordered_set<std::string> extract_file_strings(const fs::path& p, const ExtractOptions& eopt)
{
    const auto data = read_file_bytes(p);
    std::unordered_set<std::string> out;
    if (data.empty()) return out;
    extract_ascii(data, eopt, out);
    if (eopt.do_utf8) extract_utf8(data, eopt, out);
    if (eopt.do_utf16) extract_utf16(data, eopt, out);
    return out;
}

// ---------- Location finding ----------
// Match type bitmask
static constexpr std::uint32_t MT_ASCII = 1u << 0;
static constexpr std::uint32_t MT_UTF8 = 1u << 1;
static constexpr std::uint32_t MT_UTF16LE = 1u << 2;
static constexpr std::uint32_t MT_UTF16BE = 1u << 3;

struct Location
{
    fs::path file;
    std::size_t start;
    std::size_t end;
    std::uint32_t types = 0;
};

static std::vector<std::string> mask_to_type_strings(std::uint32_t m)
{
    std::vector<std::string> v;
    if (m & MT_ASCII) v.emplace_back("ascii");
    if (m & MT_UTF8) v.emplace_back("utf-8");
    if (m & MT_UTF16LE) v.emplace_back("utf-16le");
    if (m & MT_UTF16BE) v.emplace_back("utf-16be");
    return v;
}

// ---------- Ignore list ----------
static std::unordered_set<std::string> load_ignorelist(const fs::path& p, bool ignore_case)
{
    std::unordered_set<std::string> bl;
    std::ifstream ifs(p);
    if (!ifs)
    {
        log(LogLevel::warn, "Could not open ignore list: {}", p.string());
        return bl;
    }
    std::string line;
    while (std::getline(ifs, line))
    {
        // trim CR and surrounding whitespace
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto l = line.find_first_not_of(" \t");
        if (l == std::string::npos) continue;
        auto r = line.find_last_not_of(" \t");
        std::string v = line.substr(l, r - l + 1);
        if (v.empty() || v[0] == '#') continue;
        if (ignore_case) v = to_lower_ascii_str(v);
        bl.insert(std::move(v));
    }
    log(LogLevel::info, "Loaded {} ignore entrie(s) from {}", bl.size(), p.string());
    return bl;
}

static std::vector<std::uint16_t> utf8_to_utf16_units(const std::string& s)
{
    std::vector<std::uint16_t> units;
    units.reserve(s.size());
    const auto* b = reinterpret_cast<const std::uint8_t*>(s.data());
    const std::size_t n = s.size();
    std::size_t i = 0;
    while (i < n)
    {
        auto dec = decode_utf8(b + i, n - i);
        if (!dec)
        {
            ++i;
            continue;
        }
        auto [cp, len] = *dec;
        i += len;
        if (cp <= 0xFFFF)
        {
            if (cp >= 0xD800 && cp <= 0xDFFF) continue; // skip lone surrogates
            units.push_back(static_cast<std::uint16_t>(cp));
        }
        else
        {
            cp -= 0x10000;
            std::uint16_t hi = 0xD800 | static_cast<std::uint16_t>((cp >> 10) & 0x3FF);
            std::uint16_t lo = 0xDC00 | static_cast<std::uint16_t>(cp & 0x3FF);
            units.push_back(hi);
            units.push_back(lo);
        }
    }
    return units;
}

static std::vector<std::size_t> find_occurrences(const std::vector<std::uint8_t>& hay,
                                                 const std::vector<std::uint8_t>& needle)
{
    std::vector<std::size_t> offs;
    if (needle.empty() || hay.size() < needle.size()) return offs;
    const std::size_t n = hay.size(), m = needle.size();
    for (std::size_t i = 0; i + m <= n;)
    {
        if (hay[i] == needle[0] && std::memcmp(hay.data() + i, needle.data(), m) == 0)
        {
            offs.push_back(i);
            i += 1; // allow overlaps
        }
        else ++i;
    }
    return offs;
}

static std::vector<std::size_t> find_occurrences_ci_ascii(const std::vector<std::uint8_t>& hay,
                                                          const std::vector<std::uint8_t>& needle_lower)
{
    std::vector<std::size_t> offs;
    const std::size_t n = hay.size(), m = needle_lower.size();
    if (m == 0 || n < m) return offs;
    for (std::size_t i = 0; i + m <= n; ++i)
    {
        bool ok = true;
        for (std::size_t j = 0; j < m; ++j)
        {
            if (to_lower_ascii(hay[i + j]) != needle_lower[j])
            {
                ok = false;
                break;
            }
        }
        if (ok) offs.push_back(i);
    }
    return offs;
}

static bool equal_ci_utf16_at(const std::vector<std::uint8_t>& hay, std::size_t start,
                              const std::vector<std::uint8_t>& needle, Endian e)
{
    const std::size_t m = needle.size();
    for (std::size_t j = 0; j < m; j += 2)
    {
        std::uint8_t hb0 = hay[start + j], hb1 = hay[start + j + 1];
        const std::uint8_t nb0 = needle[j];
        const std::uint8_t nb1 = needle[j + 1];
        if (e == Endian::LE)
        {
            if (hb1 == 0x00 && hb0 >= 'A' && hb0 <= 'Z') hb0 = static_cast<std::uint8_t>(hb0 + 32);
        }
        else
        {
            if (hb0 == 0x00 && hb1 >= 'A' && hb1 <= 'Z') hb1 = static_cast<std::uint8_t>(hb1 + 32);
        }
        if (hb0 != nb0 || hb1 != nb1) return false;
    }
    return true;
}

static std::vector<std::size_t> find_occurrences_ci_utf16(const std::vector<std::uint8_t>& hay,
                                                          const std::vector<std::uint8_t>& needle,
                                                          Endian e)
{
    std::vector<std::size_t> offs;
    const std::size_t n = hay.size(), m = needle.size();
    if (m == 0 || n < m) return offs;
    for (std::size_t i = 0; i + m <= n; ++i)
    {
        if (equal_ci_utf16_at(hay, i, needle, e)) offs.push_back(i);
    }
    return offs;
}

static std::vector<Location> find_locations_in_file(const fs::path& p, const std::string& s,
                                                    const ExtractOptions& eopt, bool ignore_case)
{
    std::map<std::pair<std::size_t, std::size_t>, std::uint32_t> acc;
    const auto data = read_file_bytes(p);
    if (data.empty() || s.empty()) return {};

    // ASCII/UTF-8 search
    {
        const std::string sn = ignore_case ? to_lower_ascii_str(s) : s;
        const std::vector<std::uint8_t> needle(sn.begin(), sn.end());
        const auto offs = ignore_case
                              ? find_occurrences_ci_ascii(data, needle)
                              : find_occurrences(data, needle);
        if (!offs.empty())
        {
            const bool is_ascii_only = std::ranges::all_of(needle.begin(), needle.end(),
                                                           [](const std::uint8_t b) { return b < 0x80; });
            const std::uint32_t t = is_ascii_only ? (MT_ASCII | MT_UTF8) : MT_UTF8;
            for (const auto off : offs)
            {
                acc[{off, off + needle.size()}] |= t;
            }
        }
    }

    // UTF-16 search if enabled
    if (eopt.do_utf16)
    {
        if (const auto units = utf8_to_utf16_units(s); !units.empty())
        {
            auto search16 = [&](const Endian e)
            {
                std::vector<std::uint8_t> needle;
                needle.reserve(units.size() * 2);
                for (const auto u : units)
                {
                    if (e == Endian::LE)
                    {
                        needle.push_back(static_cast<std::uint8_t>(u & 0xFF));
                        needle.push_back(static_cast<std::uint8_t>(u >> 8));
                    }
                    else
                    {
                        needle.push_back(static_cast<std::uint8_t>(u >> 8));
                        needle.push_back(static_cast<std::uint8_t>(u & 0xFF));
                    }
                }
                const auto offs = ignore_case
                                      ? find_occurrences_ci_utf16(data, needle, e)
                                      : find_occurrences(data, needle);
                if (!offs.empty())
                {
                    for (const auto off : offs)
                    {
                        acc[{off, off + needle.size()}] |= (e == Endian::LE ? MT_UTF16LE : MT_UTF16BE);
                    }
                }
            };
            switch (eopt.utf16_mode)
            {
            case Options::Utf16Mode::auto_bom:
            case Options::Utf16Mode::both:
                search16(Endian::LE);
                search16(Endian::BE);
                break;
            case Options::Utf16Mode::le:
                search16(Endian::LE);
                break;
            case Options::Utf16Mode::be:
                search16(Endian::BE);
                break;
            }
        }
    }

    std::vector<Location> out;
    out.reserve(acc.size());
    for (const auto& [range, mask] : acc) out.push_back(Location{p, range.first, range.second, mask});
    return out;
}

// ---------- Grouping ----------
struct Group
{
    std::string name;
    std::vector<fs::path> files;
};

static bool is_hidden(const fs::directory_entry& de)
{
    if (const auto name = de.path().filename().string(); !name.empty() && name[0] == '.') return true;
#ifdef _WIN32
    // Also check Windows hidden attribute
    DWORD attrs = GetFileAttributesW(de.path().wstring().c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_HIDDEN)) return true;
#endif
    return false;
}

static std::vector<Group> collect_groups(const fs::path& root, bool include_hidden)
{
    std::vector<Group> groups;
    if (!fs::exists(root) || !fs::is_directory(root))
    {
        log(LogLevel::error, "Root is not a directory: {}", root.string());
        return groups;
    }
    std::vector<fs::directory_entry> entries;
    for (auto const& de : fs::directory_iterator(root, fs::directory_options::skip_permission_denied)
         | std::views::filter([&](auto const& e)
         {
             if (!include_hidden && is_hidden(e)) return false;
             return e.is_regular_file() || e.is_directory();
         }))
    {
        if (de.is_regular_file()) groups.push_back(Group{de.path().filename().string(), {de.path()}});
        else if (de.is_directory())
        {
            Group g{de.path().filename().string(), {}};
            for (auto it = fs::recursive_directory_iterator(
                     de.path(), fs::directory_options::skip_permission_denied);
                 it != fs::recursive_directory_iterator(); ++it)
            {
                const auto& rde = *it;
                if (!include_hidden && is_hidden(rde))
                {
                    if (rde.is_directory()) it.disable_recursion_pending();
                    continue;
                }
                if (rde.is_regular_file()) g.files.push_back(rde.path());
            }
            groups.push_back(std::move(g));
        }
    }
    std::ranges::sort(groups, {}, &Group::name);
    return groups;
}

// ---------- Exact string-set intersection ----------
static std::vector<std::string> intersect_all(const std::vector<std::unordered_set<std::string>>& sets)
{
    if (sets.empty()) return {};
    std::unordered_map<std::string, std::size_t> freq;
    for (auto const& s : sets)
    {
        for (auto const& str : s)
        {
            if (auto it = freq.find(str); it == freq.end()) freq.emplace(str, 1);
            else ++(it->second);
        }
    }
    const auto need = sets.size();
    std::vector<std::string> inter;
    inter.reserve(freq.size());
    for (auto& [k, v] : freq) if (v == need) inter.push_back(k);
    std::ranges::sort(inter);
    return inter;
}

// ========== Substring (k-gram) machinery ==========
struct KGramIndex
{
    std::vector<std::uint64_t> hashes_sorted;
};

struct RK
{
    std::uint64_t base, powK, h = 0;
    std::size_t k, filled = 0;
    std::deque<std::uint32_t> win;

    explicit RK(const std::size_t k, const std::uint64_t base = 1315423911u) : base(base), powK(1), k(k)
    {
        for (std::size_t i = 1; i < k; ++i) powK *= base;
    }

    bool push(const std::uint32_t cp)
    {
        if (k == 0) return false;
        if (filled == k)
        {
            h -= static_cast<std::uint64_t>(win.front()) * powK;
            win.pop_front();
        }
        else ++filled;
        h = h * base + cp;
        win.push_back(cp);
        return filled == k;
    }
};

static void add_kgrams_utf8(const std::string& s, const std::size_t K, std::vector<std::uint64_t>& out)
{
    if (s.empty() || K == 0) return;
    RK rk(K);
    const auto* b = reinterpret_cast<const std::uint8_t*>(s.data());
    const std::size_t n = s.size();
    std::size_t i = 0;
    while (i < n)
    {
        auto dec = decode_utf8(b + i, n - i);
        if (!dec)
        {
            rk = RK(K);
            ++i;
            continue;
        }
        auto [cp, len] = *dec;
        i += len;
        if (!is_printable_codepoint(cp))
        {
            rk = RK(K);
            continue;
        }
        if (rk.push(cp)) out.push_back(rk.h);
    }
}

static KGramIndex build_group_kgrams(const std::unordered_set<std::string>& strings, const std::size_t K)
{
    std::vector<std::uint64_t> hs;
    std::size_t total = 0;
    for (auto& s : strings) total += s.size();
    hs.reserve(total);
    for (auto& s : strings) add_kgrams_utf8(s, K, hs);
    std::ranges::sort(hs);
    auto r = std::ranges::unique(hs);
    hs.erase(r.begin(), r.end());
    return {std::move(hs)};
}

static std::vector<std::uint64_t> intersect_sorted_hashes(std::vector<std::vector<std::uint64_t>> vecs)
{
    if (vecs.empty()) return {};
    for (auto& v : vecs) std::ranges::sort(v);
    std::vector<std::uint64_t> acc = std::move(vecs[0]);
    for (std::size_t i = 1; i < vecs.size(); ++i)
    {
        std::vector<std::uint64_t> tmp;
        tmp.reserve(std::min(acc.size(), vecs[i].size()));
        std::ranges::set_intersection(acc, vecs[i], std::back_inserter(tmp));
        acc.swap(tmp);
        if (acc.empty()) break;
    }
    return acc;
}

struct CPMap
{
    std::vector<std::uint32_t> cps;
    std::vector<std::size_t> byte_off;
};

static CPMap to_cp_map(const std::string& s)
{
    CPMap m;
    m.cps.reserve(s.size());
    m.byte_off.reserve(s.size());
    const auto* b = reinterpret_cast<const std::uint8_t*>(s.data());
    const std::size_t n = s.size();
    std::size_t i = 0;
    while (i < n)
    {
        auto dec = decode_utf8(b + i, n - i);
        if (!dec)
        {
            ++i;
            continue;
        }
        auto [cp, len] = *dec;
        if (!is_printable_codepoint(cp))
        {
            i += len;
            continue;
        }
        m.byte_off.push_back(i);
        m.cps.push_back(cp);
        i += len;
    }
    return m;
}

static std::string slice_utf8_bytes(const std::string& s, const CPMap& m, const std::size_t left,
                                    const std::size_t right)
{
    const auto start = m.byte_off[left];
    const auto end = (right + 1 < m.byte_off.size()) ? m.byte_off[right + 1] : s.size();
    return s.substr(start, end - start);
}

static bool appears_in_all_groups(const std::string& needle, const std::vector<std::string>& group_blobs)
{
    return std::ranges::all_of(group_blobs, [&](auto const& blob) { return blob.find(needle) != std::string::npos; });
}

static std::vector<std::string> dedupe_maximals(std::vector<std::string> subs)
{
    std::ranges::sort(subs, [](auto const& a, auto const& b)
    {
        if (a.size() != b.size()) return a.size() > b.size();
        return a < b;
    });
    std::vector<std::string> kept;
    for (auto const& s : subs)
    {
        bool contained = false;
        for (auto const& big : kept)
        {
            if (big.find(s) != std::string::npos)
            {
                contained = true;
                break;
            }
        }
        if (!contained) kept.push_back(s);
    }
    return kept;
}

static std::vector<std::string> materialize_max_substrings_from_group0(
    const std::unordered_set<std::string>& group0_strings,
    const std::unordered_set<std::uint64_t>& inter_hashes,
    const std::vector<std::string>& group_blobs,
    std::size_t K)
{
    std::unordered_set<std::string> results_set;
    for (auto const& s : group0_strings)
    {
        if (s.empty()) continue;
        auto m = to_cp_map(s);
        if (m.cps.size() < K) continue;
        RK rk(K);
        std::size_t j = 0;
        while (j < m.cps.size())
        {
            if (rk.push(m.cps[j]))
            {
                if (auto h = rk.h; inter_hashes.contains(h))
                {
                    std::size_t left = j - K + 1, right = j;
                    bool progressed = true;
                    while (progressed)
                    {
                        progressed = false;
                        if (left > 0)
                        {
                            if (auto cand = slice_utf8_bytes(s, m, left - 1, right); appears_in_all_groups(
                                cand, group_blobs))
                            {
                                --left;
                                progressed = true;
                            }
                        }
                        if (right + 1 < m.cps.size())
                        {
                            if (auto cand = slice_utf8_bytes(s, m, left, right + 1); appears_in_all_groups(
                                cand, group_blobs))
                            {
                                ++right;
                                progressed = true;
                            }
                        }
                    }
                    auto best = slice_utf8_bytes(s, m, left, right);
                    results_set.insert(std::move(best));
                    j = right + 1;
                    rk = RK(K);
                    continue;
                }
            }
            ++j;
        }
    }
    std::vector results(results_set.begin(), results_set.end());
    return dedupe_maximals(std::move(results));
}

// ---------- Main ----------
int main(int argc, char** argv)
{
    auto popt = parse_args(argc, argv);
    if (!popt) return 1;
    if (popt->help)
    {
        print_help();
        return 0;
    }
    const auto& opt = *popt;
    g_debug = opt.verbose; // enable -v

    log(LogLevel::info, "Scanning root: {}", opt.root.string());

    auto groups = collect_groups(opt.root, opt.include_hidden);
    if (groups.empty())
    {
        log(LogLevel::warn, "No files or subfolders found.");
        return 0;
    }

    log(LogLevel::info, "Discovered {} group(s).", groups.size());
    for (auto const& g : groups) log(LogLevel::debug, "Group '{}' with {} file(s)", g.name, g.files.size());

    ExtractOptions eopt{
        .min_len = opt.min_len, .do_utf8 = !opt.skip_utf8, .do_utf16 = !opt.skip_utf16, .utf16_mode = opt.utf16_mode
    };

    // Process groups in parallel
    std::vector<std::future<std::unordered_set<std::string>>> futures;
    futures.reserve(groups.size());
    for (auto const& g : groups)
    {
        futures.emplace_back(std::async(std::launch::async, [&eopt, &g]
        {
            std::unordered_set<std::string> merged;
            for (auto const& p : g.files)
            {
                auto ss = extract_file_strings(p, eopt);
                merged.insert(ss.begin(), ss.end());
            }
            return merged;
        }));
    }

    std::vector<std::unordered_set<std::string>> sets;
    sets.reserve(groups.size());
    for (auto& fut : futures) sets.push_back(fut.get());

    // Diagnostics & optional empty-group filtering
    std::vector<std::unordered_set<std::string>> sets_considered;
    sets_considered.reserve(sets.size());
    std::vector<std::string> group_names;
    group_names.reserve(groups.size());
    std::vector<Group> groups_considered;
    groups_considered.reserve(groups.size());
    std::size_t empty_cnt = 0;
    for (std::size_t i = 0; i < sets.size(); ++i)
    {
        auto sz = sets[i].size();
        if (sz == 0) ++empty_cnt;
        log(LogLevel::info, "Group '{}' -> {} strings", groups[i].name, sz);
        if (opt.strict_groups || sz > 0)
        {
            if (opt.ignore_case)
            {
                std::unordered_set<std::string> norm;
                norm.reserve(sets[i].size());
                for (auto const& s : sets[i]) norm.insert(to_lower_ascii_str(s));
                sets_considered.push_back(std::move(norm));
            }
            else
            {
                sets_considered.push_back(std::move(sets[i]));
            }
            group_names.push_back(groups[i].name);
            groups_considered.push_back(groups[i]);
        }
        else { log(LogLevel::warn, "Dropping empty group '{}' (use --strict-groups to include)", groups[i].name); }
    }

    if (sets_considered.size() < 2)
    {
        if (opt.strict_groups && empty_cnt > 0)
            log(LogLevel::warn,
                "--strict-groups enabled and {} empty group(s) present; intersections likely empty.",
                empty_cnt);
        else log(LogLevel::warn, "Fewer than 2 non-empty groups remain; nothing to intersect.");
    }

    if (!opt.substr_mode)
    {
        // ---------- Exact mode ----------
        auto inter = intersect_all(sets_considered);
        // Apply ignorelist if provided
        std::unordered_set<std::string> ignorelist;
        if (opt.ignorelist_path) ignorelist = load_ignorelist(*opt.ignorelist_path, opt.ignore_case);
        if (!ignorelist.empty())
        {
            std::vector<std::string> filtered;
            filtered.reserve(inter.size());
            for (auto const& s : inter) if (!ignorelist.contains(s)) filtered.push_back(s);
            inter.swap(filtered);
        }
        std::println("{}[RESULT]{} {} string(s) in intersection:", ansi::blue, ansi::reset, inter.size());
        for (auto const& s : inter)
        {
            if (!opt.show_locations && opt.show_types)
            {
                std::uint32_t agg = 0;
                for (auto const& g : groups_considered)
                    for (auto const& p : g.files)
                        for (auto const& loc : find_locations_in_file(p, s, eopt, opt.ignore_case)) agg |= loc.types;
                auto ts = mask_to_type_strings(agg);
                std::string joined;
                for (std::size_t i = 0; i < ts.size(); ++i)
                {
                    if (i) joined += ", ";
                    joined += ts[i];
                }
                if (!joined.empty()) std::println("{} ({})", s, joined);
                else std::println("{}", s);
            }
            else
            {
                std::println("{}", s);
            }
            if (opt.show_locations)
            {
                std::vector<Location> locs;
                for (auto const& g : groups_considered)
                    for (auto const& p : g.files)
                    {
                        auto ls = find_locations_in_file(p, s, eopt, opt.ignore_case);
                        locs.insert(locs.end(), ls.begin(), ls.end());
                    }
                std::ranges::sort(locs, [](auto const& a, auto const& b)
                {
                    auto an = a.file.generic_string();
                    auto bn = b.file.generic_string();
                    if (an != bn) return an < bn;
                    if (a.start != b.start) return a.start < b.start;
                    return a.end < b.end;
                });
                for (const auto& L : locs)
                {
                    std::error_code ec;
                    auto rel = fs::relative(L.file, opt.root, ec);
                    auto name = (ec ? L.file : rel).generic_string();
                    if (opt.show_types)
                    {
                        auto ts = mask_to_type_strings(L.types);
                        std::string joined;
                        for (std::size_t i = 0; i < ts.size(); ++i)
                        {
                            if (i) joined += ", ";
                            joined += ts[i];
                        }
                        std::println("    {}:{}:{} ({})", name, L.start, L.end, joined);
                    }
                    else
                    {
                        std::println("    {}:{}:{}", name, L.start, L.end);
                    }
                }
            }
        }
        if (opt.output)
        {
            std::ofstream ofs(*opt.output, std::ios::binary);
            if (!ofs)
            {
                log(LogLevel::error, "Failed to open output: {}", opt.output->string());
                return 1;
            }
            for (auto const& s : inter)
            {
                ofs.write(s.data(), static_cast<std::streamsize>(s.size()));
                ofs.put('\n');
            }
            log(LogLevel::info, "Wrote intersection to {} ({} lines)", opt.output->string(), inter.size());
        }
        return 0;
    }

    // ---------- Substring mode ----------
    const std::size_t K = opt.gram_len;
    log(LogLevel::info, "Substring mode ON (K = {})", K);

    // Build group blobs for validation and extension
    std::vector<std::string> group_blobs;
    group_blobs.reserve(sets_considered.size());
    for (auto const& set : sets_considered)
    {
        std::size_t total = 0;
        for (auto const& s : set) total += s.size() + 1;
        std::string blob;
        blob.reserve(total);
        for (auto const& s : set)
        {
            blob.append(s);
            blob.push_back('\0');
        }
        group_blobs.push_back(std::move(blob));
    }

    // Build k-gram indices per group and log sizes
    std::vector<std::vector<std::uint64_t>> all_hashes;
    all_hashes.reserve(sets_considered.size());
    for (std::size_t i = 0; i < sets_considered.size(); ++i)
    {
        auto [hashes_sorted] = build_group_kgrams(sets_considered[i], K);
        log(LogLevel::info, "Group '{}' -> {} unique K-grams", group_names[i], hashes_sorted.size());
        all_hashes.push_back(std::move(hashes_sorted));
    }

    auto inter_hashes_vec = intersect_sorted_hashes(std::move(all_hashes));
    std::unordered_set inter_hashes(inter_hashes_vec.begin(), inter_hashes_vec.end());
    log(LogLevel::info, "{} common K-grams across groups", inter_hashes.size());

    if (inter_hashes.empty())
    {
        log(LogLevel::warn, "No common substrings of length {} found{}.", K, opt.strict_groups ? " (strict mode)" : "");
        return 0;
    }

    auto results = materialize_max_substrings_from_group0(sets_considered.front(), inter_hashes, group_blobs, K);

    auto count_codepoints = [](const std::string& s)
    {
        std::size_t i = 0, c = 0;
        const std::size_t n = s.size();
        const auto* b = reinterpret_cast<const std::uint8_t*>(s.data());
        while (i < n)
        {
            auto dec = decode_utf8(b + i, n - i);
            if (!dec)
            {
                ++i;
                continue;
            }
            auto [cp,len] = *dec;
            i += len;
            if (is_printable_codepoint(cp)) ++c;
        }
        return c;
    };

    std::vector<std::string> final_results;
    for (auto const& s : results)
    {
        if (count_codepoints(s) < K) continue;
        if (appears_in_all_groups(s, group_blobs)) final_results.push_back(s);
    }

    // Apply ignorelist if provided
    std::unordered_set<std::string> ignorelist;
    if (opt.ignorelist_path) ignorelist = load_ignorelist(*opt.ignorelist_path, opt.ignore_case);
    if (!ignorelist.empty())
    {
        std::vector<std::string> filtered;
        filtered.reserve(final_results.size());
        for (auto const& s : final_results) if (!ignorelist.contains(s)) filtered.push_back(s);
        final_results.swap(filtered);
    }

    std::ranges::sort(final_results, [](auto const& a, auto const& b)
    {
        if (a.size() != b.size()) return a.size() > b.size();
        return a < b;
    });

    std::println("{}[RESULT]{} {} maximal common substring(s) (K = {}):", ansi::blue, ansi::reset, final_results.size(),
                 K);
    for (auto const& s : final_results)
    {
        if (!opt.show_locations && opt.show_types)
        {
            std::uint32_t agg = 0;
            for (const auto& [name, files] : groups_considered)
                for (auto const& p : files)
                    for (auto const& loc : find_locations_in_file(p, s, eopt, opt.ignore_case)) agg |= loc.types;
            auto ts = mask_to_type_strings(agg);
            std::string joined;
            for (std::size_t i = 0; i < ts.size(); ++i)
            {
                if (i) joined += ", ";
                joined += ts[i];
            }
            if (!joined.empty()) std::println("{} ({})", s, joined);
            else std::println("{}", s);
        }
        else
        {
            std::println("{}", s);
        }
        if (opt.show_locations)
        {
            std::vector<Location> locs;
            for (const auto& [name, files] : groups_considered)
                for (auto const& p : files)
                {
                    auto ls = find_locations_in_file(p, s, eopt, opt.ignore_case);
                    locs.insert(locs.end(), ls.begin(), ls.end());
                }
            std::ranges::sort(locs, [](auto const& a, auto const& b)
            {
                auto an = a.file.generic_string();
                auto bn = b.file.generic_string();
                if (an != bn) return an < bn;
                if (a.start != b.start) return a.start < b.start;
                return a.end < b.end;
            });
            for (const auto& L : locs)
            {
                std::error_code ec;
                auto rel = fs::relative(L.file, opt.root, ec);
                auto name = (ec ? L.file : rel).generic_string();
                if (opt.show_types)
                {
                    auto ts = mask_to_type_strings(L.types);
                    std::string joined;
                    for (std::size_t i = 0; i < ts.size(); ++i)
                    {
                        if (i) joined += ", ";
                        joined += ts[i];
                    }
                    std::println("    {}:{}:{} ({})", name, L.start, L.end, joined);
                }
                else
                {
                    std::println("    {}:{}:{}", name, L.start, L.end);
                }
            }
        }
    }

    if (opt.output)
    {
        std::ofstream ofs(*opt.output, std::ios::binary);
        if (!ofs)
        {
            log(LogLevel::error, "Failed to open output: {}", opt.output->string());
            return 1;
        }
        for (auto const& s : final_results)
        {
            ofs.write(s.data(), static_cast<std::streamsize>(s.size()));
            ofs.put('\n');
        }
        log(LogLevel::info, "Wrote substrings to {} ({} lines)", opt.output->string(), final_results.size());
    }

    return 0;
}
