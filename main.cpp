// strings_intersect.cpp
// C++23 program to extract printable strings (ASCII, UTF-8, UTF-16) from files,
// group them by top-level entry (files individually; first-level subfolders merged recursively),
// compute the intersection across all groups, and print / optionally write to a file.
//
// Requirements honored:
//  - C++23, modern ranges, std::print for logging with ANSI colors
//  - CLI: folder (positional), --min-len, --skip-utf8, --skip-utf16, --utf16-endian, --output, --help
//  - Endianness: UTF-16 LE / BE / both / auto (BOM-aware)
//  - Parallelization: group-level parallelism via std::async
//  - No external libs beyond the C++ standard library (LIEF optional, not used here)

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <optional>
#include <print>
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
namespace ansi {
    constexpr std::string_view reset = "\x1b[0m";
    constexpr std::string_view green = "\x1b[32m";
    constexpr std::string_view yellow = "\x1b[33m";
    constexpr std::string_view red = "\x1b[31m";
    constexpr std::string_view blue = "\x1b[34m";
    constexpr std::string_view magenta = "\x1b[35m";
}

enum class LogLevel { info, warn, error, debug };

static bool g_debug = false; // toggle with env or edit as needed

template<class... Ts>
void log(LogLevel lvl, std::format_string<Ts...> fmt, Ts&&... args) {
    auto tag = [lvl]{
        switch (lvl){
            case LogLevel::info: return "INFO"sv;
            case LogLevel::warn: return "WARN"sv;
            case LogLevel::error: return "ERR "sv;
            case LogLevel::debug: return "DBG "sv;
        }
        return "INFO"sv;
    }();
    auto color = [lvl]{
        switch (lvl){
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
struct Options {
    fs::path root;
    std::optional<fs::path> output;
    std::size_t min_len = 4;            // minimum length in characters (code points for UTF-8/16)
    bool skip_utf8 = false;
    bool skip_utf16 = false;
    enum class Utf16Mode { auto_bom, le, be, both } utf16_mode = Utf16Mode::both;
    bool help = false;
};

static void print_help() {
    std::print(
R"(strings_intersect - Extract strings from files and print the intersection across groups

USAGE:
  strings_intersect <folder> [options]

Groups:
  - Each top-level FILE under <folder> forms its own group.
  - Each first-level SUBFOLDER is scanned recursively; all its files merge into one group.
  - The final output is the intersection of all groups' string sets.

Options:
  -m, --min-len <N>       Minimum string length to include (default: 4)
      --skip-utf8         Skip scanning for UTF-8 strings
      --skip-utf16        Skip scanning for UTF-16 strings
      --utf16-endian <MODE>
                          One of: auto | le | be | both (default: both)
  -o, --output <file>     Write intersection to file (one per line)
  -h, --help              Show this help and exit

Notes:
  * ASCII scanning is always enabled.
  * UTF-16 endianness: 'auto' honors a BOM if present; 'both' scans as LE and BE.
  * Uses C++23 std::print for logging; colors use ANSI escapes.
)"
    );
}

static std::optional<std::size_t> parse_size(const std::string_view sv) {
    std::size_t v{}; auto* first = sv.data(); auto* last = sv.data()+sv.size();
    if (auto [ptr, ec] = std::from_chars(first, last, v); ec == std::errc() && ptr == last) return v;
    return std::nullopt;
}

static std::optional<Options> parse_args(const int argc, char** argv){
    if (argc <= 1) { print_help(); return std::nullopt; }
    Options opt{};
    std::vector<std::string_view> args(argv+1, argv+argc);

    // positional folder (first non-flag)
    bool folder_set = false;
    for (const auto a : args){
        if (a == "-h" || a == "--help") { opt.help = true; return opt; }
    }

    for (std::size_t i = 0; i < args.size(); ++i){
        auto a = args[i];
        if (!a.empty() && a[0] != '-') {
            if (!folder_set) { opt.root = fs::path(std::string(a)); folder_set = true; continue; }
        }
        if (a == "-m"sv || a == "--min-len"sv) {
            if (i+1 >= args.size()) { log(LogLevel::error, "Missing value for {}", a); return std::nullopt; }
            auto val = parse_size(args[++i]);
            if (!val) { log(LogLevel::error, "Invalid number for --min-len: {}", args[i]); return std::nullopt; }
            opt.min_len = *val;
        } else if (a == "--skip-utf8"sv) {
            opt.skip_utf8 = true;
        } else if (a == "--skip-utf16"sv) {
            opt.skip_utf16 = true;
        } else if (a == "--utf16-endian"sv) {
            if (i+1 >= args.size()) { log(LogLevel::error, "Missing value for --utf16-endian"); return std::nullopt; }
            if (auto v = args[++i]; v == "auto"sv) opt.utf16_mode = Options::Utf16Mode::auto_bom;
            else if (v == "le"sv) opt.utf16_mode = Options::Utf16Mode::le;
            else if (v == "be"sv) opt.utf16_mode = Options::Utf16Mode::be;
            else if (v == "both"sv) opt.utf16_mode = Options::Utf16Mode::both;
            else { log(LogLevel::error, "Invalid --utf16-endian: {} (use auto|le|be|both)", v); return std::nullopt; }
        } else if (a == "-o"sv || a == "--output"sv) {
            if (i+1 >= args.size()) { log(LogLevel::error, "Missing value for {}", a); return std::nullopt; }
            opt.output = fs::path(std::string(args[++i]));
        } else if (a == "-h"sv || a == "--help"sv) {
            opt.help = true;
            return opt;
        } else if (!a.empty() && a[0] == '-') {
            log(LogLevel::warn, "Unknown option: {}", a);
            return std::nullopt;
        }
    }
    if (!folder_set) { log(LogLevel::error, "Missing <folder> positional argument"); return std::nullopt; }
    return opt;
}

// ---------- File reading ----------
static std::vector<std::uint8_t> read_file_bytes(const fs::path& p){
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
static inline bool is_printable_ascii(const std::uint8_t b){
    return b >= 0x20 && b <= 0x7E; // space..~
}

static inline bool is_printable_codepoint(const char32_t cp){
    // exclude C0/C1 controls, surrogates, noncharacters
    if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) return false;
    if (cp > 0x10FFFF) return false;
    if (cp >= 0xD800 && cp <= 0xDFFF) return false; // surrogate range
    if ((cp & 0xFFFE) == 0xFFFE) return false;     // U+FFFE, U+FFFF, etc.
    if (cp >= 0xFDD0 && cp <= 0xFDEF) return false; // noncharacters
    // allow SPACE but reject common line breaks
    if (cp == U'\n' || cp == U'\r' || cp == U'\t') return false;
    return true;
}

static inline void append_utf8(std::string& out, const char32_t cp){
    if (cp <= 0x7F) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

static inline bool is_cont_byte(const std::uint8_t b){ return (b & 0xC0) == 0x80; }

static std::optional<std::pair<char32_t, std::size_t>> decode_utf8(const std::uint8_t* s, const std::size_t n){
    if (n == 0) return std::nullopt;
    std::uint8_t b0 = s[0];
    if (b0 <= 0x7F) return {{b0, 1}};
    if (b0 >= 0xC2 && b0 <= 0xDF) { // 2 bytes
        if (n < 2 || !is_cont_byte(s[1])) return std::nullopt;
        char32_t cp = ((b0 & 0x1F) << 6) | (s[1] & 0x3F);
        return {{cp, 2}};
    }
    if (b0 == 0xE0) {
        if (n < 3 || !(s[1] >= 0xA0 && s[1] <= 0xBF) || !is_cont_byte(s[2])) return std::nullopt;
        char32_t cp = ((b0 & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return {{cp, 3}};
    }
    if (b0 >= 0xE1 && b0 <= 0xEC) {
        if (n < 3 || !is_cont_byte(s[1]) || !is_cont_byte(s[2])) return std::nullopt;
        char32_t cp = ((b0 & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return {{cp, 3}};
    }
    if (b0 == 0xED) {
        if (n < 3 || !(s[1] >= 0x80 && s[1] <= 0x9F) || !is_cont_byte(s[2])) return std::nullopt; // avoid surrogates
        char32_t cp = ((b0 & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return {{cp, 3}};
    }
    if (b0 >= 0xEE && b0 <= 0xEF) {
        if (n < 3 || !is_cont_byte(s[1]) || !is_cont_byte(s[2])) return std::nullopt;
        char32_t cp = ((b0 & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return {{cp, 3}};
    }
    if (b0 == 0xF0) {
        if (n < 4 || !(s[1] >= 0x90 && s[1] <= 0xBF) || !is_cont_byte(s[2]) || !is_cont_byte(s[3])) return std::nullopt;
        char32_t cp = ((b0 & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return {{cp, 4}};
    }
    if (b0 >= 0xF1 && b0 <= 0xF3) {
        if (n < 4 || !is_cont_byte(s[1]) || !is_cont_byte(s[2]) || !is_cont_byte(s[3])) return std::nullopt;
        char32_t cp = ((b0 & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return {{cp, 4}};
    }
    if (b0 == 0xF4) {
        if (n < 4 || !(s[1] >= 0x80 && s[1] <= 0x8F) || !is_cont_byte(s[2]) || !is_cont_byte(s[3])) return std::nullopt;
        char32_t cp = ((b0 & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return {{cp, 4}};
    }
    return std::nullopt;
}

// ---------- Extractors ----------
struct ExtractOptions {
    std::size_t min_len;
    bool do_utf8;
    bool do_utf16;
    Options::Utf16Mode utf16_mode;
};

static void extract_ascii(const std::vector<std::uint8_t>& data, const ExtractOptions& eopt, std::unordered_set<std::string>& out){
    std::size_t i = 0;
    const std::size_t n = data.size();
    while (i < n) {
        // skip non-printable
        while (i < n && !is_printable_ascii(data[i])) ++i;
        const auto start = i;
        while (i < n && is_printable_ascii(data[i])) ++i;
        if (i > start && (i - start) >= eopt.min_len) {
            out.emplace(reinterpret_cast<const char*>(data.data()+start), i - start);
        }
    }
}

static void extract_utf8(const std::vector<std::uint8_t>& data, const ExtractOptions& eopt, std::unordered_set<std::string>& out){
    std::size_t i = 0;
    const std::size_t n = data.size();
    std::string current;
    std::size_t cp_count = 0;
    auto flush = [&]{ if (cp_count >= eopt.min_len) out.emplace(current); current.clear(); cp_count = 0; };

    while (i < n){
        auto dec = decode_utf8(data.data()+i, n - i);
        if (!dec) { flush(); ++i; continue; }
        auto [cp, len] = *dec;
        if (!is_printable_codepoint(cp)) { flush(); i += len; continue; }
        // append original encoded bytes to preserve exact UTF-8
        current.append(reinterpret_cast<const char*>(data.data()+i), len);
        ++cp_count;
        i += len;
    }
    flush();
}

enum class Endian { LE, BE };

static std::optional<Endian> bom_to_endian(const std::vector<std::uint8_t>& data){
    if (data.size() >= 2){
        if (data[0] == 0xFF && data[1] == 0xFE) return Endian::LE; // UTF-16LE BOM
        if (data[0] == 0xFE && data[1] == 0xFF) return Endian::BE; // UTF-16BE BOM
    }
    return std::nullopt;
}

static inline std::uint16_t load16(const std::uint8_t* p, const Endian e){
    return (e == Endian::LE) ? (static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8))
                             : (static_cast<std::uint16_t>(p[1]) | (static_cast<std::uint16_t>(p[0]) << 8));
}

static void extract_utf16_pass(const std::vector<std::uint8_t>& data, const Endian e, const ExtractOptions& eopt, std::unordered_set<std::string>& out){
    if (data.size() < 2) return;
    std::size_t i = 0;
    const std::size_t n = data.size();
    std::string current; // in UTF-8
    std::size_t cp_count = 0;
    auto flush = [&]{ if (cp_count >= eopt.min_len) out.emplace(current); current.clear(); cp_count = 0; };

    while (i + 1 < n){
        const std::uint16_t u = load16(&data[i], e); i += 2;
        if (u == 0xFEFF) { // BOM (if encountered mid-file, treat as boundary)
            flush();
            continue;
        }
        char32_t cp = 0;
        if (u >= 0xD800 && u <= 0xDBFF) { // high surrogate
            if (i + 1 >= n) { flush(); break; }
            if (const std::uint16_t u2 = load16(&data[i], e); u2 >= 0xDC00 && u2 <= 0xDFFF) {
                i += 2;
                cp = 0x10000 + (((u - 0xD800) << 10) | (u2 - 0xDC00));
            } else {
                // invalid pair: boundary
                flush();
                continue;
            }
        } else if (u >= 0xDC00 && u <= 0xDFFF) {
            // stray low surrogate: boundary
            flush();
            continue;
        } else {
            cp = u;
        }
        if (!is_printable_codepoint(cp)) { flush(); continue; }
        append_utf8(current, cp);
        ++cp_count;
    }
    flush();
}

static void extract_utf16(const std::vector<std::uint8_t>& data, const ExtractOptions& eopt, std::unordered_set<std::string>& out){
    if (data.size() < 2) return;
    const auto bom = bom_to_endian(data);
    switch (eopt.utf16_mode){
        case Options::Utf16Mode::auto_bom:
            if (bom) extract_utf16_pass(data, *bom, eopt, out);
            else {
                // No BOM: try both, they may capture different strings embedded mid-file
                extract_utf16_pass(data, Endian::LE, eopt, out);
                extract_utf16_pass(data, Endian::BE, eopt, out);
            }
            break;
        case Options::Utf16Mode::le:
            extract_utf16_pass(data, Endian::LE, eopt, out);
            break;
        case Options::Utf16Mode::be:
            extract_utf16_pass(data, Endian::BE, eopt, out);
            break;
        case Options::Utf16Mode::both:
            extract_utf16_pass(data, Endian::LE, eopt, out);
            extract_utf16_pass(data, Endian::BE, eopt, out);
            break;
    }
}

static std::unordered_set<std::string> extract_file_strings(const fs::path& p, const ExtractOptions& eopt){
    const auto data = read_file_bytes(p);
    std::unordered_set<std::string> out;
    if (data.empty()) return out;
    extract_ascii(data, eopt, out);
    if (eopt.do_utf8)  extract_utf8(data, eopt, out);
    if (eopt.do_utf16) extract_utf16(data, eopt, out);
    return out;
}

// ---------- Grouping ----------
struct Group {
    std::string name;             // file name or subfolder name
    std::vector<fs::path> files;  // files in this group
};

static std::vector<Group> collect_groups(const fs::path& root){
    std::vector<Group> groups;
    if (!fs::exists(root) || !fs::is_directory(root)) {
        log(LogLevel::error, "Root is not a directory: {}", root.string());
        return groups;
    }

    std::vector<fs::directory_entry> entries;
    for (auto const& de : fs::directory_iterator(root, fs::directory_options::skip_permission_denied)) entries.push_back(de);

    // files -> individual groups; dirs -> merged recursive group
    for (auto const& de : entries | std::views::filter([](auto const& e){ return e.is_regular_file() || e.is_directory(); })){
        if (de.is_regular_file()) {
            groups.push_back(Group{ de.path().filename().string(), { de.path() } });
        } else if (de.is_directory()) {
            Group g{ de.path().filename().string(), {} };
            for (auto const& rde : fs::recursive_directory_iterator(de.path(), fs::directory_options::skip_permission_denied)){
                if (rde.is_regular_file()) g.files.push_back(rde.path());
            }
            groups.push_back(std::move(g));
        }
    }
    // Stable order by name for determinism
    std::ranges::sort(groups, {}, &Group::name);
    return groups;
}

// ---------- Intersection ----------
static std::vector<std::string> intersect_all(const std::vector<std::unordered_set<std::string>>& sets){
    if (sets.empty()) return {};
    std::unordered_map<std::string, std::size_t> freq;
    freq.reserve(1024);
    for (auto const& s : sets){
        for (auto const& str : s) {
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

// ---------- Main ----------
int main(int argc, char** argv){
    auto popt = parse_args(argc, argv);
    if (!popt) return 1;
    if (popt->help) { print_help(); return 0; }

    const auto& opt = *popt;
    log(LogLevel::info, "Scanning root: {}", opt.root.string());

    auto groups = collect_groups(opt.root);
    if (groups.empty()) { log(LogLevel::warn, "No files or subfolders found."); return 0; }

    log(LogLevel::info, "Discovered {} group(s).", groups.size());
    for (auto const& g : groups) log(LogLevel::debug, "Group '{}' with {} file(s)", g.name, g.files.size());

    ExtractOptions eopt{
        .min_len = opt.min_len,
        .do_utf8 = !opt.skip_utf8,
        .do_utf16 = !opt.skip_utf16,
        .utf16_mode = opt.utf16_mode
    };

    // Process groups in parallel
    std::vector<std::future<std::unordered_set<std::string>>> futures;
    futures.reserve(groups.size());

    for (auto const& g : groups){
        futures.emplace_back(std::async(std::launch::async, [&eopt, &g]{
            std::unordered_set<std::string> merged;
            for (auto const& p : g.files){
                auto ss = extract_file_strings(p, eopt);
                // merge
                merged.insert(ss.begin(), ss.end());
            }
            return merged;
        }));
    }

    std::vector<std::unordered_set<std::string>> sets;
    sets.reserve(groups.size());
    for (auto& fut : futures) sets.push_back(fut.get());

    // Intersection across groups
    auto inter = intersect_all(sets);

    std::println("{}[RESULT]{} {} string(s) in intersection:", ansi::blue, ansi::reset, inter.size());
    for (auto const& s : inter) {
        std::println("{}", s);
    }

    if (opt.output) {
        std::ofstream ofs(*opt.output, std::ios::binary);
        if (!ofs) {
            log(LogLevel::error, "Failed to open output: {}", opt.output->string());
            return 1;
        }
        for (auto const& s : inter) {
            ofs.write(s.data(), static_cast<std::streamsize>(s.size()));
            ofs.put('\n');
        }
        log(LogLevel::info, "Wrote intersection to {} ({} lines)", opt.output->string(), inter.size());
    }

    return 0;
}
