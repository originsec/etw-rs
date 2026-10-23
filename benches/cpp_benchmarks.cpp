// ETW Parser Benchmarks - C++ Edition
// Compares krabsetw, TdhFormatProperty, and TdhGetProperty performance
//
// Build with MSVC:
//   cl /EHsc /std:c++17 /O2 /W4 /DHAVE_KRABSETW /DUNICODE /D_UNICODE /I path\to\krabsetw\krabs cpp_benchmarks.cpp tdh.lib advapi32.lib
//
// Or with CMake (recommended for krabsetw dependency management)

// Define these before any Windows headers to avoid krabsetw conflicts
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#ifdef HAVE_KRABSETW
#include <krabs.hpp>
#endif

#include "captured_events.h"
#include <windows.h>
#include <tdh.h>
#include <evntcons.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <unordered_map>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <memory>
#include <sddl.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std::chrono;

// =============================================================================
// CPU Pinning for Hybrid Architectures
// =============================================================================

/// Opt this process out of execution-speed power throttling.
///
/// Mirrors disable_power_throttling() in benches/bench_util.rs. Power throttling is a
/// per-process setting and is NOT inherited, so the Rust harness opting itself out
/// does nothing for this child process. Without this, the combined table would report
/// an unthrottled Rust half beside a throttled C++ half -- precisely the mismatch that
/// table exists to eliminate. Measured on the Rust side at -55% for the same work.
void disable_power_throttling() {
    PROCESS_POWER_THROTTLING_STATE state{};
    state.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    state.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    state.StateMask = 0;  // zero state + EXECUTION_SPEED control == always full speed

    if (!SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling,
                               &state, sizeof(state))) {
        std::cerr << "CPU pinning: could not opt out of power throttling (error "
                  << GetLastError() << "). Refusing to report timings.\n";
        std::exit(1);
    }
}

/// Pin this process to the performance cores of a hybrid CPU.
///
/// Enumerates CPU sets, selects the highest EfficiencyClass, and confines the process
/// to those cores with a hard affinity mask, verifying the mask and this thread's
/// residency afterwards. On non-hybrid machines only the throttling opt-out applies.
///
/// A hard mask is deliberate: SetProcessDefaultCpuSets, used here previously, is only
/// a scheduling hint the kernel may ignore, and the old code printed "pinned to N
/// P-cores" whether or not anything had been pinned. Every failure now exits rather
/// than reporting a figure, because a timing taken off the performance cores or under
/// a throttle is not comparable with the Rust arms it is printed beside.
void pin_to_performance_cores() {
    disable_power_throttling();

    ULONG size = 0;
    GetSystemCpuSetInformation(nullptr, 0, &size, GetCurrentProcess(), 0);
    if (size == 0) return;

    std::vector<BYTE> buffer(size);
    if (!GetSystemCpuSetInformation(
            reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(buffer.data()),
            size, &size, GetCurrentProcess(), 0))
        return;

    // Walk variable-sized entries to find max EfficiencyClass
    BYTE max_eff = 0;
    ULONG total_cores = 0;
    ULONG offset = 0;
    while (offset < size) {
        auto* info = reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(buffer.data() + offset);
        if (info->Size == 0 || offset + info->Size > size) break;
        if (info->Type == CpuSetInformation) {
            if (info->CpuSet.EfficiencyClass > max_eff)
                max_eff = info->CpuSet.EfficiencyClass;
            total_cores++;
        }
        offset += info->Size;
    }

    // Collect the performance cores, by group and index within that group.
    struct PerfCore { WORD group; BYTE index; };
    std::vector<PerfCore> perf;
    offset = 0;
    while (offset < size) {
        auto* info = reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(buffer.data() + offset);
        if (info->Size == 0 || offset + info->Size > size) break;
        if (info->Type == CpuSetInformation && info->CpuSet.EfficiencyClass == max_eff)
            perf.push_back({info->CpuSet.Group, info->CpuSet.LogicalProcessorIndex});
        offset += info->Size;
    }

    // Only pin if the performance cores are a strict subset, i.e. a hybrid CPU.
    if (perf.empty() || perf.size() >= total_cores) {
        std::cerr << "CPU pinning: all " << total_cores
                  << " cores are EfficiencyClass " << static_cast<int>(max_eff)
                  << " (non-hybrid), no pinning needed\n";
        return;
    }

    // SetProcessAffinityMask addresses one processor group. A machine large enough to
    // split performance cores across groups needs SetThreadGroupAffinity; rather than
    // silently pinning to part of the set, stop.
    for (const auto& core : perf) {
        if (core.group != perf.front().group) {
            std::cerr << "CPU pinning: performance cores span multiple processor groups, "
                         "which SetProcessAffinityMask cannot express. "
                         "Refusing to report timings.\n";
            std::exit(1);
        }
    }

    DWORD_PTR mask = 0;
    for (const auto& core : perf) mask |= static_cast<DWORD_PTR>(1) << core.index;

    if (!SetProcessAffinityMask(GetCurrentProcess(), mask)) {
        std::cerr << "CPU pinning: SetProcessAffinityMask failed (error "
                  << GetLastError() << "). Refusing to report timings.\n";
        std::exit(1);
    }

    // Read the mask back rather than trusting the setter.
    DWORD_PTR applied = 0, system_mask = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &applied, &system_mask) || applied != mask) {
        std::cerr << "CPU pinning: affinity mask read back incorrectly. "
                     "Refusing to report timings.\n";
        std::exit(1);
    }

    // Affinity takes effect on reschedule, so yield before giving up.
    for (int attempt = 0; attempt < 8; ++attempt) {
        DWORD current = GetCurrentProcessorNumber();
        if (mask & (static_cast<DWORD_PTR>(1) << current)) {
            std::cerr << "CPU pinning: confined to " << perf.size()
                      << " P-cores (EfficiencyClass " << static_cast<int>(max_eff)
                      << ") of " << total_cores << ", running on CPU " << current << "\n";
            return;
        }
        SwitchToThread();
    }

    std::cerr << "CPU pinning: affinity mask applied but this thread is still outside "
                 "the performance set. Refusing to report timings.\n";
    std::exit(1);
}

// =============================================================================
// Timing Breakdown Infrastructure
// =============================================================================

struct TimingBreakdown {
    double schema_construction_ns = 0.0;
    double parser_construction_ns = 0.0;
    double property_parsing_ns = 0.0;
    double total_overhead_ns = 0.0;

    void print(const std::string& name) const {
        std::cout << "\n" << name << " Timing Breakdown:\n";
        std::cout << "  Schema construction:  " << std::fixed << std::setprecision(1)
                  << schema_construction_ns << " ns\n";
        std::cout << "  Parser construction:  " << parser_construction_ns << " ns\n";
        std::cout << "  Property parsing:     " << property_parsing_ns << " ns\n";
        std::cout << "  ----------------------------------------\n";
        std::cout << "  Total overhead:       " << total_overhead_ns << " ns\n";
    }
};

// High-precision timer using QueryPerformanceCounter
class HiResTimer {
private:
    LARGE_INTEGER frequency_;
    LARGE_INTEGER start_;

public:
    HiResTimer() {
        QueryPerformanceFrequency(&frequency_);
    }

    void start() {
        QueryPerformanceCounter(&start_);
    }

    double elapsed_ns() const {
        LARGE_INTEGER end;
        QueryPerformanceCounter(&end);
        return ((end.QuadPart - start_.QuadPart) * 1000000000.0) / frequency_.QuadPart;
    }
};

// =============================================================================
// Optimisation Barrier
// =============================================================================

// Prevents MSVC dead-store elimination at /O2.
// For structs with std::wstring fields, MSVC can prove the strings are never
// read and eliminate the heap allocation entirely. __declspec(noinline) prevents
// inlining so MSVC cannot prove the value is unused.
template<typename T>
__declspec(noinline) void DoNotOptimize(const T& value) {
    volatile auto sink = reinterpret_cast<const volatile char*>(&value);
    (void)sink;
}

// =============================================================================
// Parsed Event Structures
// =============================================================================

struct ParsedProcessStart {
    int64_t timestamp;
    uint32_t process_id;
    uint64_t process_sequence_number;
    int64_t create_time;
    uint32_t parent_process_id;
    uint64_t parent_process_sequence_number;
    uint32_t session_id;
    uint32_t flags;
    uint32_t process_token_elevation_type;
    uint32_t process_token_is_elevated;
    std::wstring mandatory_label; // SID formatted as "S-1-..." string
    std::wstring image_name;
    uint32_t image_checksum;
    uint32_t time_date_stamp;
    std::wstring package_full_name;
    std::wstring package_relative_app_id;
    uint32_t security_mitigations;
};

struct ParsedThreadStart {
    int64_t timestamp;
    uint32_t process_id;
    uint32_t thread_id;
    uint64_t stack_base;
    uint64_t stack_limit;
    uint64_t user_stack_base;
    uint64_t user_stack_limit;
    uint64_t start_addr;
    uint64_t win32_start_addr;
    uint64_t teb_base;
    uint32_t sub_process_tag;
};

struct ParsedFileCreate {
    int64_t timestamp;
    uint64_t irp;
    uint64_t file_object;
    uint32_t issuing_thread_id;
    uint32_t create_options;
    uint32_t create_attributes;
    uint32_t share_access;
    std::wstring file_name;
};

struct ParsedRegistryCreateKey {
    int64_t timestamp;
    uint64_t base_object;
    uint64_t key_object;
    uint32_t status;
    uint32_t disposition;
    std::wstring base_name;
    std::wstring relative_name;
};

struct ParsedRpcClientCall {
    int64_t timestamp;
    GUID interface_uuid;
    uint32_t proc_num;
    uint32_t protocol;
    std::wstring network_address;
    std::wstring endpoint;
    std::wstring options;
    uint32_t authentication_level;
    uint32_t authentication_service;
    uint32_t impersonation_level;
};

// Naive result structures — all event properties stored as wide strings.
// Models how a developer unfamiliar with ETW might write using TdhFormatProperty
// as a universal formatter for every field, integer or string alike.
struct ParsedProcessStartNaive {
    int64_t timestamp;
    std::wstring process_id;
    std::wstring process_sequence_number;
    std::wstring create_time;
    std::wstring parent_process_id;
    std::wstring parent_process_sequence_number;
    std::wstring session_id;
    std::wstring flags;
    std::wstring process_token_elevation_type;
    std::wstring process_token_is_elevated;
    std::wstring mandatory_label;
    std::wstring image_name;
    std::wstring image_checksum;
    std::wstring time_date_stamp;
    std::wstring package_full_name;
    std::wstring package_relative_app_id;
    std::wstring security_mitigations;
};

struct ParsedThreadStartNaive {
    int64_t timestamp;
    std::wstring process_id;
    std::wstring thread_id;
    std::wstring stack_base;
    std::wstring stack_limit;
    std::wstring user_stack_base;
    std::wstring user_stack_limit;
    std::wstring start_addr;
    std::wstring win32_start_addr;
    std::wstring teb_base;
    std::wstring sub_process_tag;
};

struct ParsedFileCreateNaive {
    int64_t timestamp;
    std::wstring irp;
    std::wstring file_object;
    std::wstring issuing_thread_id;
    std::wstring create_options;
    std::wstring create_attributes;
    std::wstring share_access;
    std::wstring file_name;
};

struct ParsedRegistryCreateKeyNaive {
    int64_t timestamp;
    std::wstring base_object;
    std::wstring key_object;
    std::wstring status;
    std::wstring disposition;
    std::wstring base_name;
    std::wstring relative_name;
};

struct ParsedRpcClientCallNaive {
    int64_t timestamp;
    std::wstring interface_uuid;
    std::wstring proc_num;
    std::wstring protocol;
    std::wstring network_address;
    std::wstring endpoint;
    std::wstring options;
    std::wstring authentication_level;
    std::wstring authentication_service;
    std::wstring impersonation_level;
};

// =============================================================================
// TDH Helper Functions
// =============================================================================

// Get TDH schema for an event
std::vector<uint8_t> get_tdh_schema(const EVENT_RECORD* event) {
    ULONG size = 0;

    // First call to get size
    ULONG status = TdhGetEventInformation(const_cast<EVENT_RECORD*>(event), 0, nullptr, nullptr, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return {};
    }

    // Allocate and get schema
    std::vector<uint8_t> buffer(size);
    status = TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(event),
        0,
        nullptr,
        reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data()),
        &size
    );

    if (status != ERROR_SUCCESS) {
        return {};
    }

    return buffer;
}

/// A schema cache with a real lookup, as krabsetw and etw-rs both have.
///
/// Keyed on provider, event id and version because that is how a consumer must key
/// it: a real trace interleaves event types, so the last schema fetched cannot be
/// assumed to still apply. The lookup is therefore part of what a cache costs, and
/// pricing it in is the difference between measuring a cache and measuring a
/// best case that no consumer gets.
///
/// std::unordered_map is deliberately the default container a C++ consumer would
/// reach for, not a tuned one. krabsetw and etw-rs each bring their own.
struct SchemaKey {
    GUID provider;
    USHORT id;
    UCHAR version;

    bool operator==(const SchemaKey& other) const {
        return id == other.id && version == other.version &&
               memcmp(&provider, &other.provider, sizeof(GUID)) == 0;
    }
};

struct SchemaKeyHash {
    // Hashes the fields rather than the struct bytes: SchemaKey has padding, and
    // hashing padding would make lookups depend on uninitialised memory.
    size_t operator()(const SchemaKey& k) const {
        size_t h = 1469598103934665603ULL;
        const auto* guid = reinterpret_cast<const uint8_t*>(&k.provider);
        for (size_t i = 0; i < sizeof(GUID); ++i) {
            h = (h ^ guid[i]) * 1099511628211ULL;
        }
        h = (h ^ static_cast<size_t>(k.id)) * 1099511628211ULL;
        h = (h ^ static_cast<size_t>(k.version)) * 1099511628211ULL;
        return h;
    }
};

class SchemaCache {
public:
    /// Return the cached schema for this event, fetching it on first sight.
    const std::vector<uint8_t>& get(const EVENT_RECORD& record) {
        SchemaKey key{record.EventHeader.ProviderId, record.EventHeader.EventDescriptor.Id,
                      record.EventHeader.EventDescriptor.Version};
        auto it = entries_.find(key);
        if (it == entries_.end()) {
            it = entries_.emplace(key, get_tdh_schema(&record)).first;
        }
        return it->second;
    }

private:
    std::unordered_map<SchemaKey, std::vector<uint8_t>, SchemaKeyHash> entries_;
};

// Validate that an event matches the expected layout by checking:
//   1. EventDescriptor.Id matches expected_event_id
//   2. Each property name in EventPropertyInfoArray matches the expected list
// Kernel trace events do not set EventNameOffset, so EventName is not a reliable
// discriminator — property names and event ID are.
bool validate_event_layout(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record,
    uint16_t expected_event_id,
    std::initializer_list<const wchar_t*> expected_names
) {
    if (record.EventHeader.EventDescriptor.Id != expected_event_id) return false;

    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    const auto* base = reinterpret_cast<const uint8_t*>(pTei);
    auto count = static_cast<ULONG>(expected_names.size());

    if (pTei->PropertyCount < count) return false;

    ULONG idx = 0;
    for (const wchar_t* name : expected_names) {
        const wchar_t* actual = reinterpret_cast<const wchar_t*>(
            base + pTei->EventPropertyInfoArray[idx].NameOffset);
        if (wcscmp(actual, name) != 0) return false;
        ++idx;
    }
    return true;
}

// Read a fixed-size value directly from the event data buffer, advancing ptr.
// Uses memcpy to handle potentially unaligned addresses safely.
// When epi is provided, asserts sizeof(T) matches the schema field size.
// epi->length == 0 means variable-length or pointer-sized field; skips the check.
template<typename T>
T read_field(const uint8_t*& ptr, const uint8_t* end,
             const EVENT_PROPERTY_INFO* epi = nullptr) {
    if (epi != nullptr) {
        const USHORT schema_len = epi->length;
        if (schema_len != 0 && schema_len != static_cast<USHORT>(sizeof(T))) {
            std::cerr << "read_field: sizeof(T)=" << sizeof(T)
                      << " does not match EventPropertyInfo.length=" << schema_len << "\n";
            std::terminate();
        }
    }
    T val{};
    if (ptr + sizeof(T) <= end) {
        memcpy(&val, ptr, sizeof(T));
        ptr += sizeof(T);
    }
    return val;
}

// Use TdhFormatProperty to format a string or complex-type field (UNICODESTRING,
// SID, etc.) and advance ptr by the number of bytes consumed.
std::wstring read_string_field(
    const TRACE_EVENT_INFO* pTei,
    const EVENT_PROPERTY_INFO& epi,
    const uint8_t*& ptr, const uint8_t* end,
    std::vector<wchar_t>& buf,
    BYTE ptr_size
) {
    if (ptr >= end) return {};
    ULONG remaining = static_cast<ULONG>(end - ptr);
    while (true) {
        ULONG buf_bytes = static_cast<ULONG>(buf.size() * sizeof(wchar_t));
        USHORT consumed = 0;
        ULONG status = TdhFormatProperty(
            const_cast<TRACE_EVENT_INFO*>(pTei), nullptr, ptr_size,
            epi.nonStructType.InType, epi.nonStructType.OutType, epi.length,
            static_cast<USHORT>(remaining), const_cast<uint8_t*>(ptr),
            &buf_bytes, buf.data(), &consumed
        );
        if (status == ERROR_INSUFFICIENT_BUFFER && buf.size() < 8192) {
            buf.resize(buf_bytes / sizeof(wchar_t) + 1);
            continue;
        }
        if (status == ERROR_SUCCESS) {
            ptr += consumed;
            size_t len = 0;
            while (len < buf.size() && buf[len]) ++len;
            return std::wstring(buf.data(), len);
        }
        break;
    }
    return {};
}

// ---------------------------------------------------------------------------
// Name-resolved, single-pass property access.
//
// A consumer of a cached schema does not know property indices; it knows names.
// The realistic shape is therefore one pass that checks the name it expects at the
// position it expects, then copies -- not two tight loops that validate everything
// and then read everything, which is faster than any real implementation and was
// flattering these columns.
//
// `cursor` is the predicted index, advanced past each property read. etw-rs instead
// learns each call position's index per schema; for an in-order reader both predict
// the same index. On a miss the name is looked up and the payload offset
// recovered by walking from `base`, because a variable-length property's position
// cannot be computed without stepping over its predecessors. That fallback costs
// more than a hit, exactly as etw-rs's does.
//
// In-order readers -- which is every benchmark here -- always hit, so the fallback
// is structural fairness rather than something these numbers exercise.
// ---------------------------------------------------------------------------

static const wchar_t* property_name(const TRACE_EVENT_INFO* pTei, ULONG idx) {
    const auto* base = reinterpret_cast<const uint8_t*>(pTei);
    return reinterpret_cast<const wchar_t*>(base + pTei->EventPropertyInfoArray[idx].NameOffset);
}

static bool name_matches(const TRACE_EVENT_INFO* pTei, ULONG idx, const wchar_t* expected) {
    return idx < pTei->PropertyCount && wcscmp(property_name(pTei, idx), expected) == 0;
}

static ULONG find_property(const TRACE_EVENT_INFO* pTei, const wchar_t* expected) {
    for (ULONG i = 0; i < pTei->PropertyCount; ++i) {
        if (wcscmp(property_name(pTei, i), expected) == 0) return i;
    }
    return pTei->PropertyCount;
}

// Bytes property `idx` occupies at `p`, or 0 if that cannot be determined.
static USHORT property_size(const TRACE_EVENT_INFO* pTei, ULONG idx, const uint8_t* p,
                            const uint8_t* end, BYTE ptr_size) {
    const auto& epi = pTei->EventPropertyInfoArray[idx];
    if (epi.length != 0) return epi.length;
    if (p >= end) return 0;

    std::vector<wchar_t> scratch(256);
    ULONG remaining = static_cast<ULONG>(end - p);
    while (true) {
        ULONG bytes = static_cast<ULONG>(scratch.size() * sizeof(wchar_t));
        USHORT consumed = 0;
        ULONG status = TdhFormatProperty(
            const_cast<TRACE_EVENT_INFO*>(pTei), nullptr, ptr_size, epi.nonStructType.InType,
            epi.nonStructType.OutType, epi.length, static_cast<USHORT>(remaining),
            const_cast<uint8_t*>(p), &bytes, scratch.data(), &consumed);
        if (status == ERROR_INSUFFICIENT_BUFFER && scratch.size() < 8192) {
            scratch.resize(bytes / sizeof(wchar_t) + 1);
            continue;
        }
        return (status == ERROR_SUCCESS) ? consumed : 0;
    }
}

// Reposition `p` to the start of property `idx` by walking from `base`.
static bool seek_property(const TRACE_EVENT_INFO* pTei, ULONG idx, const uint8_t* base,
                          const uint8_t* end, BYTE ptr_size, const uint8_t*& p) {
    p = base;
    for (ULONG i = 0; i < idx; ++i) {
        USHORT n = property_size(pTei, i, p, end, ptr_size);
        if (n == 0 || p + n > end) return false;
        p += n;
    }
    return true;
}

// Resolve `expected` to the cursor position, falling back to a name lookup.
static bool resolve(const TRACE_EVENT_INFO* pTei, const wchar_t* expected, ULONG& cursor,
                    const uint8_t*& ptr, const uint8_t* end, const uint8_t* base,
                    BYTE ptr_size) {
    if (name_matches(pTei, cursor, expected)) return true;
    ULONG idx = find_property(pTei, expected);
    if (idx >= pTei->PropertyCount) return false;
    if (!seek_property(pTei, idx, base, end, ptr_size, ptr)) return false;
    cursor = idx;
    return true;
}

template<typename T>
T get(const TRACE_EVENT_INFO* pTei, const wchar_t* expected, ULONG& cursor,
      const uint8_t*& ptr, const uint8_t* end, const uint8_t* base, BYTE ptr_size) {
    if (!resolve(pTei, expected, cursor, ptr, end, base, ptr_size)) return T{};
    T value = read_field<T>(ptr, end, &pTei->EventPropertyInfoArray[cursor]);
    ++cursor;
    return value;
}

static std::wstring get_string(const TRACE_EVENT_INFO* pTei, const wchar_t* expected,
                               ULONG& cursor, const uint8_t*& ptr, const uint8_t* end,
                               const uint8_t* base, std::vector<wchar_t>& buf, BYTE ptr_size) {
    if (!resolve(pTei, expected, cursor, ptr, end, base, ptr_size)) return {};
    auto value = read_string_field(pTei, pTei->EventPropertyInfoArray[cursor], ptr, end, buf,
                                   ptr_size);
    ++cursor;
    return value;
}

// Get raw property bytes using TdhGetProperty (random access by name).
// Used for variable-length types (SIDs, GUIDs) where the size is not known at compile time.
std::vector<uint8_t> get_tdh_property_bytes(
    const EVENT_RECORD* event,
    const wchar_t* property_name
) {
    PROPERTY_DATA_DESCRIPTOR pdd = {};
    pdd.PropertyName = reinterpret_cast<ULONGLONG>(property_name);
    pdd.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    if (TdhGetPropertySize(const_cast<EVENT_RECORD*>(event), 0, nullptr, 1, &pdd, &size)
            != ERROR_SUCCESS || size == 0) {
        return {};
    }

    std::vector<uint8_t> buffer(size);
    if (TdhGetProperty(const_cast<EVENT_RECORD*>(event), 0, nullptr, 1, &pdd,
                       size, buffer.data()) != ERROR_SUCCESS) {
        return {};
    }

    return buffer;
}

// Get a fixed-size integer property directly into a stack buffer.
// Avoids TdhGetPropertySize and heap allocation for known-size types.
template<typename T>
T get_tdh_property(
    const EVENT_RECORD* event,
    const wchar_t* property_name,
    T default_value = T{}
) {
    static_assert(std::is_integral<T>::value || std::is_same<T, GUID>::value,
                  "Use get_tdh_property_bytes for variable-length types");

    PROPERTY_DATA_DESCRIPTOR pdd = {};
    pdd.PropertyName = reinterpret_cast<ULONGLONG>(property_name);
    pdd.ArrayIndex = ULONG_MAX;

    T value{};
    if (TdhGetProperty(const_cast<EVENT_RECORD*>(event), 0, nullptr, 1, &pdd,
                       sizeof(T), reinterpret_cast<PBYTE>(&value)) != ERROR_SUCCESS) {
        return default_value;
    }

    return value;
}

// Specialisation for wide strings: one TdhGetPropertySize call, one wstring allocation.
template<>
std::wstring get_tdh_property<std::wstring>(
    const EVENT_RECORD* event,
    const wchar_t* property_name,
    std::wstring default_value
) {
    PROPERTY_DATA_DESCRIPTOR pdd = {};
    pdd.PropertyName = reinterpret_cast<ULONGLONG>(property_name);
    pdd.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    if (TdhGetPropertySize(const_cast<EVENT_RECORD*>(event), 0, nullptr, 1, &pdd, &size)
            != ERROR_SUCCESS || size < sizeof(wchar_t)) {
        return default_value;
    }

    // size is in bytes including the null terminator; write directly into wstring storage
    std::wstring result(size / sizeof(wchar_t), L'\0');
    if (TdhGetProperty(const_cast<EVENT_RECORD*>(event), 0, nullptr, 1, &pdd,
                       size, reinterpret_cast<PBYTE>(result.data())) != ERROR_SUCCESS) {
        return default_value;
    }

    // Trim null terminator(s) that TdhGetProperty appends
    while (!result.empty() && result.back() == L'\0') result.pop_back();

    return result;
}

// Print the EventName string from a cached schema buffer (once per event type,
// outside the timed region). Shows whether EventNameOffset is set so we can
// verify that check_event_name is actually comparing against a real string.
void print_event_name(const std::vector<uint8_t>& schema) {
    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    if (pTei->EventNameOffset != 0) {
        const wchar_t* w = reinterpret_cast<const wchar_t*>(schema.data() + pTei->EventNameOffset);
        std::string name;
        for (const wchar_t* p = w; *p; ++p) name += static_cast<char>(*p);
        std::cout << "EventName: \"" << name << "\" (EventNameOffset=" << pTei->EventNameOffset << ")\n";
    } else {
        std::cout << "EventName: (not set — EventNameOffset=0; validation uses EventDescriptor.Id + PropertyName iteration)\n";
    }
}

// =============================================================================
// Parser Implementations - Process Start
// =============================================================================

#ifdef HAVE_KRABSETW
ParsedProcessStart parse_process_krabsetw(
    krabs::schema_locator& locator,
    const EVENT_RECORD& record
) {
    ParsedProcessStart result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    // Use schema_locator for caching - this is how krabsetw is meant to be used
    krabs::schema schema(record, locator);
    krabs::parser parser(schema);

    result.process_id = parser.parse<uint32_t>(L"ProcessID");
    result.process_sequence_number = parser.parse<uint64_t>(L"ProcessSequenceNumber");
    result.create_time = parser.parse<int64_t>(L"CreateTime");
    result.parent_process_id = parser.parse<uint32_t>(L"ParentProcessID");
    result.parent_process_sequence_number = parser.parse<uint64_t>(L"ParentProcessSequenceNumber");
    result.session_id = parser.parse<uint32_t>(L"SessionID");
    result.flags = parser.parse<uint32_t>(L"Flags");
    result.process_token_elevation_type = parser.parse<uint32_t>(L"ProcessTokenElevationType");
    result.process_token_is_elevated = parser.parse<uint32_t>(L"ProcessTokenIsElevated");
    auto sid_result = parser.parse<krabs::sid>(L"MandatoryLabel");
    result.mandatory_label = std::wstring(sid_result.sid_string.begin(), sid_result.sid_string.end());
    result.image_name = parser.parse<std::wstring>(L"ImageName");
    result.image_checksum = parser.parse<uint32_t>(L"ImageChecksum");
    result.time_date_stamp = parser.parse<uint32_t>(L"TimeDateStamp");
    result.package_full_name = parser.parse<std::wstring>(L"PackageFullName");
    result.package_relative_app_id = parser.parse<std::wstring>(L"PackageRelativeAppId");
    result.security_mitigations = parser.parse<uint32_t>(L"SecurityMitigations");

    return result;
}

#endif

// Walk properties sequentially: direct cast for integers (no TDH call),
// TdhFormatProperty only for string/SID fields that need formatting.
ParsedProcessStart parse_process_tdh_format(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (record.EventHeader.EventDescriptor.Id != 1) return {};
    ParsedProcessStart result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    const uint8_t* base = static_cast<const uint8_t*>(record.UserData);
    const uint8_t* ptr = base;
    const uint8_t* end = base + record.UserDataLength;
    BYTE ptr_size = (record.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
    std::vector<wchar_t> buf(256);

    ULONG cursor = 0;
    result.process_id = get<uint32_t>(pTei, L"ProcessID", cursor, ptr, end, base, ptr_size);
    result.process_sequence_number = get<uint64_t>(pTei, L"ProcessSequenceNumber", cursor, ptr, end, base, ptr_size);
    result.create_time = get<int64_t>(pTei, L"CreateTime", cursor, ptr, end, base, ptr_size);
    result.parent_process_id = get<uint32_t>(pTei, L"ParentProcessID", cursor, ptr, end, base, ptr_size);
    result.parent_process_sequence_number = get<uint64_t>(pTei, L"ParentProcessSequenceNumber", cursor, ptr, end, base, ptr_size);
    result.session_id = get<uint32_t>(pTei, L"SessionID", cursor, ptr, end, base, ptr_size);
    result.flags = get<uint32_t>(pTei, L"Flags", cursor, ptr, end, base, ptr_size);
    result.process_token_elevation_type = get<uint32_t>(pTei, L"ProcessTokenElevationType", cursor, ptr, end, base, ptr_size);
    result.process_token_is_elevated = get<uint32_t>(pTei, L"ProcessTokenIsElevated", cursor, ptr, end, base, ptr_size);
    result.mandatory_label = get_string(pTei, L"MandatoryLabel", cursor, ptr, end, base, buf, ptr_size);
    result.image_name = get_string(pTei, L"ImageName", cursor, ptr, end, base, buf, ptr_size);
    result.image_checksum = get<uint32_t>(pTei, L"ImageChecksum", cursor, ptr, end, base, ptr_size);
    result.time_date_stamp = get<uint32_t>(pTei, L"TimeDateStamp", cursor, ptr, end, base, ptr_size);
    result.package_full_name = get_string(pTei, L"PackageFullName", cursor, ptr, end, base, buf, ptr_size);
    result.package_relative_app_id = get_string(pTei, L"PackageRelativeAppId", cursor, ptr, end, base, buf, ptr_size);
    result.security_mitigations = get<uint32_t>(pTei, L"SecurityMitigations", cursor, ptr, end, base, ptr_size);

    return result;
}

// Fields 0-8 are consecutive fixed-size integers — direct casts from the buffer.
// Every field retrieved via TdhGetProperty by name, as the MSDN sample recommends.
// get_tdh_property<T> skips TdhGetPropertySize for fixed-size integer/GUID types.
ParsedProcessStart parse_process_tdh_get(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (!validate_event_layout(schema, record, 1, {
        L"ProcessID", L"ProcessSequenceNumber", L"CreateTime",
        L"ParentProcessID", L"ParentProcessSequenceNumber",
        L"SessionID", L"Flags", L"ProcessTokenElevationType",
        L"ProcessTokenIsElevated", L"MandatoryLabel", L"ImageName",
        L"ImageChecksum", L"TimeDateStamp", L"PackageFullName",
        L"PackageRelativeAppId", L"SecurityMitigations"})) return {};
    ParsedProcessStart result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    result.process_id                     = get_tdh_property<uint32_t>(&record, L"ProcessID");
    result.process_sequence_number        = get_tdh_property<uint64_t>(&record, L"ProcessSequenceNumber");
    result.create_time                    = get_tdh_property<int64_t> (&record, L"CreateTime");
    result.parent_process_id              = get_tdh_property<uint32_t>(&record, L"ParentProcessID");
    result.parent_process_sequence_number = get_tdh_property<uint64_t>(&record, L"ParentProcessSequenceNumber");
    result.session_id                     = get_tdh_property<uint32_t>(&record, L"SessionID");
    result.flags                          = get_tdh_property<uint32_t>(&record, L"Flags");
    result.process_token_elevation_type   = get_tdh_property<uint32_t>(&record, L"ProcessTokenElevationType");
    result.process_token_is_elevated      = get_tdh_property<uint32_t>(&record, L"ProcessTokenIsElevated");
    {
        auto sid_bytes = get_tdh_property_bytes(&record, L"MandatoryLabel");
        if (!sid_bytes.empty()) {
            LPWSTR sid_str = nullptr;
            if (ConvertSidToStringSidW(reinterpret_cast<PSID>(sid_bytes.data()), &sid_str)) {
                result.mandatory_label = sid_str;
                LocalFree(sid_str);
            }
        }
    }
    result.image_name              = get_tdh_property<std::wstring>(&record, L"ImageName");
    result.image_checksum          = get_tdh_property<uint32_t>(&record, L"ImageChecksum");
    result.time_date_stamp         = get_tdh_property<uint32_t>(&record, L"TimeDateStamp");
    result.package_full_name       = get_tdh_property<std::wstring>(&record, L"PackageFullName");
    result.package_relative_app_id = get_tdh_property<std::wstring>(&record, L"PackageRelativeAppId");
    result.security_mitigations    = get_tdh_property<uint32_t>(&record, L"SecurityMitigations");

    return result;
}

// Naive parser: calls TdhFormatProperty for every field and stores all results
// as wide strings. This is what a developer might write without knowing that
// TdhFormatProperty is expensive for integer fields.
ParsedProcessStartNaive parse_process_tdh_fmt_naive(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (!validate_event_layout(schema, record, 1, {
        L"ProcessID", L"ProcessSequenceNumber", L"CreateTime",
        L"ParentProcessID", L"ParentProcessSequenceNumber",
        L"SessionID", L"Flags", L"ProcessTokenElevationType",
        L"ProcessTokenIsElevated", L"MandatoryLabel", L"ImageName",
        L"ImageChecksum", L"TimeDateStamp", L"PackageFullName",
        L"PackageRelativeAppId", L"SecurityMitigations"})) return {};
    ParsedProcessStartNaive result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    const uint8_t* ptr = static_cast<const uint8_t*>(record.UserData);
    const uint8_t* end = ptr + record.UserDataLength;
    BYTE ptr_size = (record.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
    std::vector<wchar_t> buf(256);

    result.process_id                     = read_string_field(pTei, pTei->EventPropertyInfoArray[0],  ptr, end, buf, ptr_size);
    result.process_sequence_number        = read_string_field(pTei, pTei->EventPropertyInfoArray[1],  ptr, end, buf, ptr_size);
    result.create_time                    = read_string_field(pTei, pTei->EventPropertyInfoArray[2],  ptr, end, buf, ptr_size);
    result.parent_process_id              = read_string_field(pTei, pTei->EventPropertyInfoArray[3],  ptr, end, buf, ptr_size);
    result.parent_process_sequence_number = read_string_field(pTei, pTei->EventPropertyInfoArray[4],  ptr, end, buf, ptr_size);
    result.session_id                     = read_string_field(pTei, pTei->EventPropertyInfoArray[5],  ptr, end, buf, ptr_size);
    result.flags                          = read_string_field(pTei, pTei->EventPropertyInfoArray[6],  ptr, end, buf, ptr_size);
    result.process_token_elevation_type   = read_string_field(pTei, pTei->EventPropertyInfoArray[7],  ptr, end, buf, ptr_size);
    result.process_token_is_elevated      = read_string_field(pTei, pTei->EventPropertyInfoArray[8],  ptr, end, buf, ptr_size);
    result.mandatory_label                = read_string_field(pTei, pTei->EventPropertyInfoArray[9],  ptr, end, buf, ptr_size);
    result.image_name                     = read_string_field(pTei, pTei->EventPropertyInfoArray[10], ptr, end, buf, ptr_size);
    result.image_checksum                 = read_string_field(pTei, pTei->EventPropertyInfoArray[11], ptr, end, buf, ptr_size);
    result.time_date_stamp                = read_string_field(pTei, pTei->EventPropertyInfoArray[12], ptr, end, buf, ptr_size);
    result.package_full_name              = read_string_field(pTei, pTei->EventPropertyInfoArray[13], ptr, end, buf, ptr_size);
    result.package_relative_app_id        = read_string_field(pTei, pTei->EventPropertyInfoArray[14], ptr, end, buf, ptr_size);
    result.security_mitigations           = read_string_field(pTei, pTei->EventPropertyInfoArray[15], ptr, end, buf, ptr_size);

    return result;
}

// =============================================================================
// Parser Implementations - Thread Start
// =============================================================================

#ifdef HAVE_KRABSETW
ParsedThreadStart parse_thread_krabsetw(
    krabs::schema_locator& locator,
    const EVENT_RECORD& record
) {
    ParsedThreadStart result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    krabs::schema schema(record, locator);
    krabs::parser parser(schema);

    result.process_id = parser.parse<uint32_t>(L"ProcessID");
    result.thread_id = parser.parse<uint32_t>(L"ThreadID");
    result.stack_base = parser.parse<uint64_t>(L"StackBase");
    result.stack_limit = parser.parse<uint64_t>(L"StackLimit");
    result.user_stack_base = parser.parse<uint64_t>(L"UserStackBase");
    result.user_stack_limit = parser.parse<uint64_t>(L"UserStackLimit");
    result.start_addr = parser.parse<uint64_t>(L"StartAddr");
    result.win32_start_addr = parser.parse<uint64_t>(L"Win32StartAddr");
    result.teb_base = parser.parse<uint64_t>(L"TebBase");
    result.sub_process_tag = parser.parse<uint32_t>(L"SubProcessTag");

    return result;
}

#endif

// All Thread Start fields are integers — zero TdhFormatProperty calls.
ParsedThreadStart parse_thread_tdh_format(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (record.EventHeader.EventDescriptor.Id != 3) return {};
    ParsedThreadStart result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    const uint8_t* base = static_cast<const uint8_t*>(record.UserData);
    const uint8_t* ptr = base;
    const uint8_t* end = base + record.UserDataLength;
    BYTE ptr_size = (record.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;

    ULONG cursor = 0;
    result.process_id = get<uint32_t>(pTei, L"ProcessID", cursor, ptr, end, base, ptr_size);
    result.thread_id = get<uint32_t>(pTei, L"ThreadID", cursor, ptr, end, base, ptr_size);
    result.stack_base = get<uint64_t>(pTei, L"StackBase", cursor, ptr, end, base, ptr_size);
    result.stack_limit = get<uint64_t>(pTei, L"StackLimit", cursor, ptr, end, base, ptr_size);
    result.user_stack_base = get<uint64_t>(pTei, L"UserStackBase", cursor, ptr, end, base, ptr_size);
    result.user_stack_limit = get<uint64_t>(pTei, L"UserStackLimit", cursor, ptr, end, base, ptr_size);
    result.start_addr = get<uint64_t>(pTei, L"StartAddr", cursor, ptr, end, base, ptr_size);
    result.win32_start_addr = get<uint64_t>(pTei, L"Win32StartAddr", cursor, ptr, end, base, ptr_size);
    result.teb_base = get<uint64_t>(pTei, L"TebBase", cursor, ptr, end, base, ptr_size);
    result.sub_process_tag = get<uint32_t>(pTei, L"SubProcessTag", cursor, ptr, end, base, ptr_size);

    return result;
}

// Every field retrieved via TdhGetProperty by name, as the MSDN sample recommends.
ParsedThreadStart parse_thread_tdh_get(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (!validate_event_layout(schema, record, 3, {
        L"ProcessID", L"ThreadID", L"StackBase", L"StackLimit",
        L"UserStackBase", L"UserStackLimit", L"StartAddr",
        L"Win32StartAddr", L"TebBase", L"SubProcessTag"})) return {};
    ParsedThreadStart result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    result.process_id       = get_tdh_property<uint32_t>(&record, L"ProcessID");
    result.thread_id        = get_tdh_property<uint32_t>(&record, L"ThreadID");
    result.stack_base       = get_tdh_property<uint64_t>(&record, L"StackBase");
    result.stack_limit      = get_tdh_property<uint64_t>(&record, L"StackLimit");
    result.user_stack_base  = get_tdh_property<uint64_t>(&record, L"UserStackBase");
    result.user_stack_limit = get_tdh_property<uint64_t>(&record, L"UserStackLimit");
    result.start_addr       = get_tdh_property<uint64_t>(&record, L"StartAddr");
    result.win32_start_addr = get_tdh_property<uint64_t>(&record, L"Win32StartAddr");
    result.teb_base         = get_tdh_property<uint64_t>(&record, L"TebBase");
    result.sub_process_tag  = get_tdh_property<uint32_t>(&record, L"SubProcessTag");

    return result;
}

// Naive parser: calls TdhFormatProperty for every field. Thread Start has only
// integer/pointer fields, so every field incurs a TdhFormatProperty call.
ParsedThreadStartNaive parse_thread_tdh_fmt_naive(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (!validate_event_layout(schema, record, 3, {
        L"ProcessID", L"ThreadID", L"StackBase", L"StackLimit",
        L"UserStackBase", L"UserStackLimit", L"StartAddr",
        L"Win32StartAddr", L"TebBase", L"SubProcessTag"})) return {};
    ParsedThreadStartNaive result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    const uint8_t* ptr = static_cast<const uint8_t*>(record.UserData);
    const uint8_t* end = ptr + record.UserDataLength;
    BYTE ptr_size = (record.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
    std::vector<wchar_t> buf(256);

    result.process_id       = read_string_field(pTei, pTei->EventPropertyInfoArray[0], ptr, end, buf, ptr_size);
    result.thread_id        = read_string_field(pTei, pTei->EventPropertyInfoArray[1], ptr, end, buf, ptr_size);
    result.stack_base       = read_string_field(pTei, pTei->EventPropertyInfoArray[2], ptr, end, buf, ptr_size);
    result.stack_limit      = read_string_field(pTei, pTei->EventPropertyInfoArray[3], ptr, end, buf, ptr_size);
    result.user_stack_base  = read_string_field(pTei, pTei->EventPropertyInfoArray[4], ptr, end, buf, ptr_size);
    result.user_stack_limit = read_string_field(pTei, pTei->EventPropertyInfoArray[5], ptr, end, buf, ptr_size);
    result.start_addr       = read_string_field(pTei, pTei->EventPropertyInfoArray[6], ptr, end, buf, ptr_size);
    result.win32_start_addr = read_string_field(pTei, pTei->EventPropertyInfoArray[7], ptr, end, buf, ptr_size);
    result.teb_base         = read_string_field(pTei, pTei->EventPropertyInfoArray[8], ptr, end, buf, ptr_size);
    result.sub_process_tag  = read_string_field(pTei, pTei->EventPropertyInfoArray[9], ptr, end, buf, ptr_size);

    return result;
}

// =============================================================================
// Parser Implementations - File Create
// =============================================================================

#ifdef HAVE_KRABSETW
ParsedFileCreate parse_file_krabsetw(
    krabs::schema_locator& locator,
    const EVENT_RECORD& record
) {
    ParsedFileCreate result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    krabs::schema schema(record, locator);
    krabs::parser parser(schema);

    result.irp = parser.parse<uint64_t>(L"Irp");
    result.file_object = parser.parse<uint64_t>(L"FileObject");
    result.issuing_thread_id = parser.parse<uint32_t>(L"IssuingThreadId");
    result.create_options = parser.parse<uint32_t>(L"CreateOptions");
    result.create_attributes = parser.parse<uint32_t>(L"CreateAttributes");
    result.share_access = parser.parse<uint32_t>(L"ShareAccess");
    result.file_name = parser.parse<std::wstring>(L"FileName");

    return result;
}

#endif

ParsedFileCreate parse_file_tdh_format(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (record.EventHeader.EventDescriptor.Id != 12) return {};
    ParsedFileCreate result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    const uint8_t* base = static_cast<const uint8_t*>(record.UserData);
    const uint8_t* ptr = base;
    const uint8_t* end = base + record.UserDataLength;
    BYTE ptr_size = (record.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
    std::vector<wchar_t> buf(256);

    ULONG cursor = 0;
    result.irp = get<uint64_t>(pTei, L"Irp", cursor, ptr, end, base, ptr_size);
    result.file_object = get<uint64_t>(pTei, L"FileObject", cursor, ptr, end, base, ptr_size);
    result.issuing_thread_id = get<uint32_t>(pTei, L"IssuingThreadId", cursor, ptr, end, base, ptr_size);
    result.create_options = get<uint32_t>(pTei, L"CreateOptions", cursor, ptr, end, base, ptr_size);
    result.create_attributes = get<uint32_t>(pTei, L"CreateAttributes", cursor, ptr, end, base, ptr_size);
    result.share_access = get<uint32_t>(pTei, L"ShareAccess", cursor, ptr, end, base, ptr_size);
    result.file_name = get_string(pTei, L"FileName", cursor, ptr, end, base, buf, ptr_size);

    return result;
}

// Every field retrieved via TdhGetProperty by name, as the MSDN sample recommends.
ParsedFileCreate parse_file_tdh_get(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (!validate_event_layout(schema, record, 12, {
        L"Irp", L"FileObject", L"IssuingThreadId",
        L"CreateOptions", L"CreateAttributes", L"ShareAccess",
        L"FileName"})) return {};
    ParsedFileCreate result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    result.irp               = get_tdh_property<uint64_t>(&record, L"Irp");
    result.file_object       = get_tdh_property<uint64_t>(&record, L"FileObject");
    result.issuing_thread_id = get_tdh_property<uint32_t>(&record, L"IssuingThreadId");
    result.create_options    = get_tdh_property<uint32_t>(&record, L"CreateOptions");
    result.create_attributes = get_tdh_property<uint32_t>(&record, L"CreateAttributes");
    result.share_access      = get_tdh_property<uint32_t>(&record, L"ShareAccess");
    result.file_name         = get_tdh_property<std::wstring>(&record, L"FileName");

    return result;
}

// Naive parser: calls TdhFormatProperty for every field including integer/pointer fields.
ParsedFileCreateNaive parse_file_tdh_fmt_naive(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (!validate_event_layout(schema, record, 12, {
        L"Irp", L"FileObject", L"IssuingThreadId",
        L"CreateOptions", L"CreateAttributes", L"ShareAccess",
        L"FileName"})) return {};
    ParsedFileCreateNaive result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    const uint8_t* ptr = static_cast<const uint8_t*>(record.UserData);
    const uint8_t* end = ptr + record.UserDataLength;
    BYTE ptr_size = (record.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
    std::vector<wchar_t> buf(256);

    result.irp               = read_string_field(pTei, pTei->EventPropertyInfoArray[0], ptr, end, buf, ptr_size);
    result.file_object       = read_string_field(pTei, pTei->EventPropertyInfoArray[1], ptr, end, buf, ptr_size);
    result.issuing_thread_id = read_string_field(pTei, pTei->EventPropertyInfoArray[2], ptr, end, buf, ptr_size);
    result.create_options    = read_string_field(pTei, pTei->EventPropertyInfoArray[3], ptr, end, buf, ptr_size);
    result.create_attributes = read_string_field(pTei, pTei->EventPropertyInfoArray[4], ptr, end, buf, ptr_size);
    result.share_access      = read_string_field(pTei, pTei->EventPropertyInfoArray[5], ptr, end, buf, ptr_size);
    result.file_name         = read_string_field(pTei, pTei->EventPropertyInfoArray[6], ptr, end, buf, ptr_size);

    return result;
}

// =============================================================================
// Parser Implementations - Registry CreateKey
// =============================================================================

#ifdef HAVE_KRABSETW
ParsedRegistryCreateKey parse_registry_krabsetw(
    krabs::schema_locator& locator,
    const EVENT_RECORD& record
) {
    ParsedRegistryCreateKey result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    krabs::schema schema(record, locator);
    krabs::parser parser(schema);

    result.base_object = parser.parse<uint64_t>(L"BaseObject");
    result.key_object = parser.parse<uint64_t>(L"KeyObject");
    result.status = parser.parse<uint32_t>(L"Status");
    result.disposition = parser.parse<uint32_t>(L"Disposition");
    result.base_name = parser.parse<std::wstring>(L"BaseName");
    result.relative_name = parser.parse<std::wstring>(L"RelativeName");

    return result;
}

#endif

ParsedRegistryCreateKey parse_registry_tdh_format(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (record.EventHeader.EventDescriptor.Id != 1) return {};
    ParsedRegistryCreateKey result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    const uint8_t* base = static_cast<const uint8_t*>(record.UserData);
    const uint8_t* ptr = base;
    const uint8_t* end = base + record.UserDataLength;
    BYTE ptr_size = (record.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
    std::vector<wchar_t> buf(256);

    ULONG cursor = 0;
    result.base_object = get<uint64_t>(pTei, L"BaseObject", cursor, ptr, end, base, ptr_size);
    result.key_object = get<uint64_t>(pTei, L"KeyObject", cursor, ptr, end, base, ptr_size);
    result.status = get<uint32_t>(pTei, L"Status", cursor, ptr, end, base, ptr_size);
    result.disposition = get<uint32_t>(pTei, L"Disposition", cursor, ptr, end, base, ptr_size);
    result.base_name = get_string(pTei, L"BaseName", cursor, ptr, end, base, buf, ptr_size);
    result.relative_name = get_string(pTei, L"RelativeName", cursor, ptr, end, base, buf, ptr_size);

    return result;
}

// Every field retrieved via TdhGetProperty by name, as the MSDN sample recommends.
ParsedRegistryCreateKey parse_registry_tdh_get(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (!validate_event_layout(schema, record, 1, {
        L"BaseObject", L"KeyObject", L"Status", L"Disposition",
        L"BaseName", L"RelativeName"})) return {};
    ParsedRegistryCreateKey result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    result.base_object   = get_tdh_property<uint64_t>(&record, L"BaseObject");
    result.key_object    = get_tdh_property<uint64_t>(&record, L"KeyObject");
    result.status        = get_tdh_property<uint32_t>(&record, L"Status");
    result.disposition   = get_tdh_property<uint32_t>(&record, L"Disposition");
    result.base_name     = get_tdh_property<std::wstring>(&record, L"BaseName");
    result.relative_name = get_tdh_property<std::wstring>(&record, L"RelativeName");

    return result;
}

// Naive parser: calls TdhFormatProperty for every field including integer/pointer fields.
ParsedRegistryCreateKeyNaive parse_registry_tdh_fmt_naive(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (!validate_event_layout(schema, record, 1, {
        L"BaseObject", L"KeyObject", L"Status", L"Disposition",
        L"BaseName", L"RelativeName"})) return {};
    ParsedRegistryCreateKeyNaive result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    const uint8_t* ptr = static_cast<const uint8_t*>(record.UserData);
    const uint8_t* end = ptr + record.UserDataLength;
    BYTE ptr_size = (record.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
    std::vector<wchar_t> buf(256);

    result.base_object   = read_string_field(pTei, pTei->EventPropertyInfoArray[0], ptr, end, buf, ptr_size);
    result.key_object    = read_string_field(pTei, pTei->EventPropertyInfoArray[1], ptr, end, buf, ptr_size);
    result.status        = read_string_field(pTei, pTei->EventPropertyInfoArray[2], ptr, end, buf, ptr_size);
    result.disposition   = read_string_field(pTei, pTei->EventPropertyInfoArray[3], ptr, end, buf, ptr_size);
    result.base_name     = read_string_field(pTei, pTei->EventPropertyInfoArray[4], ptr, end, buf, ptr_size);
    result.relative_name = read_string_field(pTei, pTei->EventPropertyInfoArray[5], ptr, end, buf, ptr_size);

    return result;
}

// =============================================================================
// Parser Implementations - RPC Client Call
// =============================================================================

#ifdef HAVE_KRABSETW
ParsedRpcClientCall parse_rpc_krabsetw(
    krabs::schema_locator& locator,
    const EVENT_RECORD& record
) {
    ParsedRpcClientCall result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    krabs::schema schema(record, locator);
    krabs::parser parser(schema);

    result.interface_uuid = parser.parse<GUID>(L"InterfaceUuid");
    result.proc_num = parser.parse<uint32_t>(L"ProcNum");
    result.protocol = parser.parse<uint32_t>(L"Protocol");
    result.network_address = parser.parse<std::wstring>(L"NetworkAddress");
    result.endpoint = parser.parse<std::wstring>(L"Endpoint");
    result.options = parser.parse<std::wstring>(L"Options");
    result.authentication_level = parser.parse<uint32_t>(L"AuthenticationLevel");
    result.authentication_service = parser.parse<uint32_t>(L"AuthenticationService");
    result.impersonation_level = parser.parse<uint32_t>(L"ImpersonationLevel");

    return result;
}

#endif

ParsedRpcClientCall parse_rpc_tdh_format(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (record.EventHeader.EventDescriptor.Id != 5) return {};
    ParsedRpcClientCall result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    const uint8_t* base = static_cast<const uint8_t*>(record.UserData);
    const uint8_t* ptr = base;
    const uint8_t* end = base + record.UserDataLength;
    BYTE ptr_size = (record.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
    std::vector<wchar_t> buf(256);

    // InterfaceUuid: GUID (16 bytes fixed) — direct read, no TdhFormatProperty
    ULONG cursor = 0;
    result.interface_uuid = get<GUID>(pTei, L"InterfaceUuid", cursor, ptr, end, base, ptr_size);

    result.proc_num = get<uint32_t>(pTei, L"ProcNum", cursor, ptr, end, base, ptr_size);
    result.protocol = get<uint32_t>(pTei, L"Protocol", cursor, ptr, end, base, ptr_size);
    result.network_address = get_string(pTei, L"NetworkAddress", cursor, ptr, end, base, buf, ptr_size);
    result.endpoint = get_string(pTei, L"Endpoint", cursor, ptr, end, base, buf, ptr_size);
    result.options = get_string(pTei, L"Options", cursor, ptr, end, base, buf, ptr_size);
    result.authentication_level = get<uint32_t>(pTei, L"AuthenticationLevel", cursor, ptr, end, base, ptr_size);
    result.authentication_service = get<uint32_t>(pTei, L"AuthenticationService", cursor, ptr, end, base, ptr_size);
    result.impersonation_level = get<uint32_t>(pTei, L"ImpersonationLevel", cursor, ptr, end, base, ptr_size);

    return result;
}

// Every field retrieved via TdhGetProperty by name, as the MSDN sample recommends.
ParsedRpcClientCall parse_rpc_tdh_get(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (!validate_event_layout(schema, record, 5, {
        L"InterfaceUuid", L"ProcNum", L"Protocol",
        L"NetworkAddress", L"Endpoint", L"Options",
        L"AuthenticationLevel", L"AuthenticationService",
        L"ImpersonationLevel"})) return {};
    ParsedRpcClientCall result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    result.interface_uuid = get_tdh_property<GUID>(&record, L"InterfaceUuid");

    result.proc_num               = get_tdh_property<uint32_t>(&record, L"ProcNum");
    result.protocol               = get_tdh_property<uint32_t>(&record, L"Protocol");
    result.network_address        = get_tdh_property<std::wstring>(&record, L"NetworkAddress");
    result.endpoint               = get_tdh_property<std::wstring>(&record, L"Endpoint");
    result.options                = get_tdh_property<std::wstring>(&record, L"Options");
    result.authentication_level   = get_tdh_property<uint32_t>(&record, L"AuthenticationLevel");
    result.authentication_service = get_tdh_property<uint32_t>(&record, L"AuthenticationService");
    result.impersonation_level    = get_tdh_property<uint32_t>(&record, L"ImpersonationLevel");

    return result;
}

// Naive parser: calls TdhFormatProperty for every field. The GUID field is
// formatted as L"{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" by TdhFormatProperty.
ParsedRpcClientCallNaive parse_rpc_tdh_fmt_naive(
    const std::vector<uint8_t>& schema,
    const EVENT_RECORD& record
) {
    if (!validate_event_layout(schema, record, 5, {
        L"InterfaceUuid", L"ProcNum", L"Protocol",
        L"NetworkAddress", L"Endpoint", L"Options",
        L"AuthenticationLevel", L"AuthenticationService",
        L"ImpersonationLevel"})) return {};
    ParsedRpcClientCallNaive result = {};
    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    auto* pTei = reinterpret_cast<const TRACE_EVENT_INFO*>(schema.data());
    const uint8_t* ptr = static_cast<const uint8_t*>(record.UserData);
    const uint8_t* end = ptr + record.UserDataLength;
    BYTE ptr_size = (record.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
    std::vector<wchar_t> buf(256);

    result.interface_uuid         = read_string_field(pTei, pTei->EventPropertyInfoArray[0], ptr, end, buf, ptr_size);
    result.proc_num               = read_string_field(pTei, pTei->EventPropertyInfoArray[1], ptr, end, buf, ptr_size);
    result.protocol               = read_string_field(pTei, pTei->EventPropertyInfoArray[2], ptr, end, buf, ptr_size);
    result.network_address        = read_string_field(pTei, pTei->EventPropertyInfoArray[3], ptr, end, buf, ptr_size);
    result.endpoint               = read_string_field(pTei, pTei->EventPropertyInfoArray[4], ptr, end, buf, ptr_size);
    result.options                = read_string_field(pTei, pTei->EventPropertyInfoArray[5], ptr, end, buf, ptr_size);
    result.authentication_level   = read_string_field(pTei, pTei->EventPropertyInfoArray[6], ptr, end, buf, ptr_size);
    result.authentication_service = read_string_field(pTei, pTei->EventPropertyInfoArray[7], ptr, end, buf, ptr_size);
    result.impersonation_level    = read_string_field(pTei, pTei->EventPropertyInfoArray[8], ptr, end, buf, ptr_size);

    return result;
}

// =============================================================================
// Benchmark Infrastructure
// =============================================================================

struct BenchmarkResult {
    std::string name;
    size_t event_count;
    double avg_ns;
    double per_event_ns;
    double median_ns;
    double median_per_event_ns;
};

template<typename ParseFunc>
BenchmarkResult benchmark_parser(
    const std::string& name,
    const std::vector<etw_capture::CapturedEvent>& events,
    ParseFunc parse_func,
    int iterations = 1000
) {
    using namespace std::chrono;

    // Warm-up (10 passes to settle icache/TDH code paths)
    for (int w = 0; w < 10; ++w) {
        for (const auto& event : events) {
            auto record = event.as_event_record();
            auto parsed = parse_func(record);
            DoNotOptimize(parsed);
        }
    }

    // Benchmark
    std::vector<double> timings;
    timings.reserve(iterations);

    for (int i = 0; i < iterations; ++i) {
        auto start = high_resolution_clock::now();

        for (const auto& event : events) {
            auto record = event.as_event_record();
            auto parsed = parse_func(record);
            DoNotOptimize(parsed);
        }

        auto end = high_resolution_clock::now();
        auto elapsed = duration_cast<nanoseconds>(end - start);
        timings.push_back(static_cast<double>(elapsed.count()));
    }

    // Sort for percentile calculations
    std::sort(timings.begin(), timings.end());

    // Median
    double median = timings[timings.size() / 2];

    // IQR-based outlier trimming
    size_t q1_idx = timings.size() / 4;
    size_t q3_idx = (timings.size() * 3) / 4;
    double q1 = timings[q1_idx];
    double q3 = timings[q3_idx];
    double iqr = q3 - q1;
    double lower = q1 - 1.5 * iqr;
    double upper = q3 + 1.5 * iqr;

    std::vector<double> trimmed;
    trimmed.reserve(timings.size());
    for (double t : timings) {
        if (t >= lower && t <= upper) trimmed.push_back(t);
    }

    double trimmed_avg = trimmed.empty()
        ? median
        : std::accumulate(trimmed.begin(), trimmed.end(), 0.0) / trimmed.size();
    double per_event = trimmed_avg / events.size();
    double median_per_event = median / events.size();

    return BenchmarkResult{
        name,
        events.size(),
        trimmed_avg,
        per_event,
        median,
        median_per_event
    };
}

void print_results(const std::vector<BenchmarkResult>& results) {
    if (results.empty()) return;

    std::cout << "\n";
    std::cout << "=======================================================================================\n";
    std::cout << "Benchmark Results (1000 iterations, IQR-trimmed mean + median)\n";
    std::cout << "=======================================================================================\n";
    std::cout << std::fixed << std::setprecision(1);

    // Find baseline (first result, trimmed mean)
    double baseline = results[0].per_event_ns;

    std::cout << std::left << std::setw(26) << "Parser"
              << std::right << std::setw(8) << "Events"
              << std::setw(16) << "Trimmed (ns/ev)"
              << std::setw(15) << "Median (ns/ev)"
              << std::setw(12) << "vs Baseline"
              << "\n";
    std::cout << "---------------------------------------------------------------------------------------\n";

    for (const auto& result : results) {
        double ratio = result.per_event_ns / baseline;
        std::cout << std::left << std::setw(26) << result.name
                  << std::right << std::setw(8) << result.event_count
                  << std::setw(16) << result.per_event_ns
                  << std::setw(15) << result.median_per_event_ns
                  << std::setw(11) << ratio << "x"
                  << "\n";
    }

    std::cout << "=======================================================================================\n";

    // Machine-readable duplicate of the median column, consumed by
    // build_and_run_cpp_benchmarks() in benches/live_events.rs so the Rust harness
    // can fold these arms into its single combined table. This is a deliberate
    // interface, not something to be replaced by scraping the human table above:
    // keep the marker, the tab separation and the field order stable.
    //
    // Median, not the trimmed mean, because median is the only statistic both
    // harnesses compute the same way.
    for (const auto& result : results) {
        std::cout << "ETWBENCH\t" << result.name
                  << "\t" << result.event_count
                  << "\t" << result.median_per_event_ns << "\n";
    }
}

// =============================================================================
// Profiling Parsers with Timing Breakdown
// =============================================================================

#ifdef HAVE_KRABSETW
// Process parser with timing breakdown
std::pair<ParsedProcessStart, TimingBreakdown> parse_process_krabsetw_profiled(
    krabs::schema_locator& locator,
    const EVENT_RECORD& record
) {
    ParsedProcessStart result = {};
    TimingBreakdown timing = {};
    HiResTimer timer;

    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    // Measure schema construction
    timer.start();
    krabs::schema schema(record, locator);
    timing.schema_construction_ns = timer.elapsed_ns();

    // Measure parser construction
    timer.start();
    krabs::parser parser(schema);
    timing.parser_construction_ns = timer.elapsed_ns();

    // Measure property parsing
    timer.start();
    result.process_id = parser.parse<uint32_t>(L"ProcessID");
    result.process_sequence_number = parser.parse<uint64_t>(L"ProcessSequenceNumber");
    result.create_time = parser.parse<int64_t>(L"CreateTime");
    result.parent_process_id = parser.parse<uint32_t>(L"ParentProcessID");
    result.parent_process_sequence_number = parser.parse<uint64_t>(L"ParentProcessSequenceNumber");
    result.session_id = parser.parse<uint32_t>(L"SessionID");
    result.flags = parser.parse<uint32_t>(L"Flags");
    result.process_token_elevation_type = parser.parse<uint32_t>(L"ProcessTokenElevationType");
    result.process_token_is_elevated = parser.parse<uint32_t>(L"ProcessTokenIsElevated");
    auto sid_result = parser.parse<krabs::sid>(L"MandatoryLabel");
    result.mandatory_label = std::wstring(sid_result.sid_string.begin(), sid_result.sid_string.end());
    result.image_name = parser.parse<std::wstring>(L"ImageName");
    result.image_checksum = parser.parse<uint32_t>(L"ImageChecksum");
    result.time_date_stamp = parser.parse<uint32_t>(L"TimeDateStamp");
    result.package_full_name = parser.parse<std::wstring>(L"PackageFullName");
    result.package_relative_app_id = parser.parse<std::wstring>(L"PackageRelativeAppId");
    result.security_mitigations = parser.parse<uint32_t>(L"SecurityMitigations");
    timing.property_parsing_ns = timer.elapsed_ns();

    timing.total_overhead_ns = timing.schema_construction_ns +
                               timing.parser_construction_ns +
                               timing.property_parsing_ns;

    return {result, timing};
}

// RPC parser with timing breakdown
std::pair<ParsedRpcClientCall, TimingBreakdown> parse_rpc_krabsetw_profiled(
    krabs::schema_locator& locator,
    const EVENT_RECORD& record
) {
    ParsedRpcClientCall result = {};
    TimingBreakdown timing = {};
    HiResTimer timer;

    result.timestamp = record.EventHeader.TimeStamp.QuadPart;

    // Measure schema construction
    timer.start();
    krabs::schema schema(record, locator);
    timing.schema_construction_ns = timer.elapsed_ns();

    // Measure parser construction
    timer.start();
    krabs::parser parser(schema);
    timing.parser_construction_ns = timer.elapsed_ns();

    // Measure property parsing
    timer.start();
    result.interface_uuid = parser.parse<GUID>(L"InterfaceUuid");
    result.proc_num = parser.parse<uint32_t>(L"ProcNum");
    result.protocol = parser.parse<uint32_t>(L"Protocol");
    result.network_address = parser.parse<std::wstring>(L"NetworkAddress");
    result.endpoint = parser.parse<std::wstring>(L"Endpoint");
    result.options = parser.parse<std::wstring>(L"Options");
    result.authentication_level = parser.parse<uint32_t>(L"AuthenticationLevel");
    result.authentication_service = parser.parse<uint32_t>(L"AuthenticationService");
    result.impersonation_level = parser.parse<uint32_t>(L"ImpersonationLevel");
    timing.property_parsing_ns = timer.elapsed_ns();

    timing.total_overhead_ns = timing.schema_construction_ns +
                               timing.parser_construction_ns +
                               timing.property_parsing_ns;

    return {result, timing};
}

// Generic profiling benchmark
template<typename ParseFunc>
TimingBreakdown profile_parser(
    const std::vector<etw_capture::CapturedEvent>& events,
    ParseFunc parse_func,
    int iterations = 1000
) {
    TimingBreakdown total = {};

    // Warm-up (10 passes)
    for (int w = 0; w < 10; ++w) {
        for (const auto& event : events) {
            auto record = event.as_event_record();
            auto [parsed, timing] = parse_func(record);
            DoNotOptimize(parsed);
        }
    }

    // Profile
    for (int i = 0; i < iterations; ++i) {
        for (const auto& event : events) {
            auto record = event.as_event_record();
            auto [parsed, timing] = parse_func(record);
            DoNotOptimize(parsed);

            total.schema_construction_ns += timing.schema_construction_ns;
            total.parser_construction_ns += timing.parser_construction_ns;
            total.property_parsing_ns += timing.property_parsing_ns;
            total.total_overhead_ns += timing.total_overhead_ns;
        }
    }

    // Average over all iterations and events
    size_t total_runs = iterations * events.size();
    total.schema_construction_ns /= total_runs;
    total.parser_construction_ns /= total_runs;
    total.property_parsing_ns /= total_runs;
    total.total_overhead_ns /= total_runs;

    return total;
}
#endif

// =============================================================================
// Pre-flight Consistency Checks
// =============================================================================
//
// Each verify_* function parses the first captured event with all available
// implementations and asserts that every field matches. Called once before
// benchmarking, outside the timed region. Terminates on any mismatch.

void verify_process_parsers_agree(const std::vector<etw_capture::CapturedEvent>& events) {
    if (events.empty()) return;
    auto record = events[0].as_event_record();
    auto schema = get_tdh_schema(&record);
    if (schema.empty()) { std::cerr << "verify_process: could not get schema\n"; return; }

    auto fmt = parse_process_tdh_format(schema, record);
    auto get = parse_process_tdh_get(schema, record);

    bool ok = true;
    auto chk = [&](bool eq, const char* field) {
        if (!eq) { std::cerr << "PREFLIGHT FAIL [Process]: " << field << " mismatch\n"; ok = false; }
    };

    chk(fmt.process_id                     == get.process_id,                     "process_id");
    chk(fmt.process_sequence_number        == get.process_sequence_number,        "process_sequence_number");
    chk(fmt.create_time                    == get.create_time,                    "create_time");
    chk(fmt.parent_process_id              == get.parent_process_id,              "parent_process_id");
    chk(fmt.parent_process_sequence_number == get.parent_process_sequence_number, "parent_process_sequence_number");
    chk(fmt.session_id                     == get.session_id,                     "session_id");
    chk(fmt.flags                          == get.flags,                          "flags");
    chk(fmt.process_token_elevation_type   == get.process_token_elevation_type,   "process_token_elevation_type");
    chk(fmt.process_token_is_elevated      == get.process_token_is_elevated,      "process_token_is_elevated");
    chk(fmt.mandatory_label                == get.mandatory_label,                "mandatory_label");
    chk(fmt.image_name                     == get.image_name,                     "image_name");
    chk(fmt.image_checksum                 == get.image_checksum,                 "image_checksum");
    chk(fmt.time_date_stamp                == get.time_date_stamp,                "time_date_stamp");
    chk(fmt.package_full_name              == get.package_full_name,              "package_full_name");
    chk(fmt.package_relative_app_id        == get.package_relative_app_id,        "package_relative_app_id");
    chk(fmt.security_mitigations           == get.security_mitigations,           "security_mitigations");

#ifdef HAVE_KRABSETW
    krabs::schema_locator locator;
    auto krabs_r = parse_process_krabsetw(locator, record);
    chk(fmt.process_id                     == krabs_r.process_id,                     "process_id (krabsetw)");
    chk(fmt.process_sequence_number        == krabs_r.process_sequence_number,        "process_sequence_number (krabsetw)");
    chk(fmt.create_time                    == krabs_r.create_time,                    "create_time (krabsetw)");
    chk(fmt.parent_process_id              == krabs_r.parent_process_id,              "parent_process_id (krabsetw)");
    chk(fmt.parent_process_sequence_number == krabs_r.parent_process_sequence_number, "parent_process_sequence_number (krabsetw)");
    chk(fmt.session_id                     == krabs_r.session_id,                     "session_id (krabsetw)");
    chk(fmt.flags                          == krabs_r.flags,                          "flags (krabsetw)");
    chk(fmt.process_token_elevation_type   == krabs_r.process_token_elevation_type,   "process_token_elevation_type (krabsetw)");
    chk(fmt.process_token_is_elevated      == krabs_r.process_token_is_elevated,      "process_token_is_elevated (krabsetw)");
    chk(fmt.mandatory_label                == krabs_r.mandatory_label,                "mandatory_label (krabsetw)");
    chk(fmt.image_name                     == krabs_r.image_name,                     "image_name (krabsetw)");
    chk(fmt.image_checksum                 == krabs_r.image_checksum,                 "image_checksum (krabsetw)");
    chk(fmt.time_date_stamp                == krabs_r.time_date_stamp,                "time_date_stamp (krabsetw)");
    chk(fmt.package_full_name              == krabs_r.package_full_name,              "package_full_name (krabsetw)");
    chk(fmt.package_relative_app_id        == krabs_r.package_relative_app_id,        "package_relative_app_id (krabsetw)");
    chk(fmt.security_mitigations           == krabs_r.security_mitigations,           "security_mitigations (krabsetw)");
#endif

    if (!ok) std::terminate();
    std::cout << "Pre-flight [Process]: TdhFormatProperty == TdhGetProperty"
#ifdef HAVE_KRABSETW
              << " == krabsetw"
#endif
              << " [OK]\n";
}

void verify_thread_parsers_agree(const std::vector<etw_capture::CapturedEvent>& events) {
    if (events.empty()) return;
    auto record = events[0].as_event_record();
    auto schema = get_tdh_schema(&record);
    if (schema.empty()) { std::cerr << "verify_thread: could not get schema\n"; return; }

    auto fmt = parse_thread_tdh_format(schema, record);
    auto get = parse_thread_tdh_get(schema, record);

    bool ok = true;
    auto chk = [&](bool eq, const char* field) {
        if (!eq) { std::cerr << "PREFLIGHT FAIL [Thread]: " << field << " mismatch\n"; ok = false; }
    };

    chk(fmt.process_id       == get.process_id,       "process_id");
    chk(fmt.thread_id        == get.thread_id,        "thread_id");
    chk(fmt.stack_base       == get.stack_base,       "stack_base");
    chk(fmt.stack_limit      == get.stack_limit,      "stack_limit");
    chk(fmt.user_stack_base  == get.user_stack_base,  "user_stack_base");
    chk(fmt.user_stack_limit == get.user_stack_limit, "user_stack_limit");
    chk(fmt.start_addr       == get.start_addr,       "start_addr");
    chk(fmt.win32_start_addr == get.win32_start_addr, "win32_start_addr");
    chk(fmt.teb_base         == get.teb_base,         "teb_base");
    chk(fmt.sub_process_tag  == get.sub_process_tag,  "sub_process_tag");

#ifdef HAVE_KRABSETW
    krabs::schema_locator locator;
    auto krabs_r = parse_thread_krabsetw(locator, record);
    chk(fmt.process_id       == krabs_r.process_id,       "process_id (krabsetw)");
    chk(fmt.thread_id        == krabs_r.thread_id,        "thread_id (krabsetw)");
    chk(fmt.stack_base       == krabs_r.stack_base,       "stack_base (krabsetw)");
    chk(fmt.stack_limit      == krabs_r.stack_limit,      "stack_limit (krabsetw)");
    chk(fmt.user_stack_base  == krabs_r.user_stack_base,  "user_stack_base (krabsetw)");
    chk(fmt.user_stack_limit == krabs_r.user_stack_limit, "user_stack_limit (krabsetw)");
    chk(fmt.start_addr       == krabs_r.start_addr,       "start_addr (krabsetw)");
    chk(fmt.win32_start_addr == krabs_r.win32_start_addr, "win32_start_addr (krabsetw)");
    chk(fmt.teb_base         == krabs_r.teb_base,         "teb_base (krabsetw)");
    chk(fmt.sub_process_tag  == krabs_r.sub_process_tag,  "sub_process_tag (krabsetw)");
#endif

    if (!ok) std::terminate();
    std::cout << "Pre-flight [Thread]:  TdhFormatProperty == TdhGetProperty"
#ifdef HAVE_KRABSETW
              << " == krabsetw"
#endif
              << " [OK]\n";
}

void verify_file_parsers_agree(const std::vector<etw_capture::CapturedEvent>& events) {
    if (events.empty()) return;
    auto record = events[0].as_event_record();
    auto schema = get_tdh_schema(&record);
    if (schema.empty()) { std::cerr << "verify_file: could not get schema\n"; return; }

    auto fmt = parse_file_tdh_format(schema, record);
    auto get = parse_file_tdh_get(schema, record);

    bool ok = true;
    auto chk = [&](bool eq, const char* field) {
        if (!eq) { std::cerr << "PREFLIGHT FAIL [File]: " << field << " mismatch\n"; ok = false; }
    };

    chk(fmt.irp               == get.irp,               "irp");
    chk(fmt.file_object       == get.file_object,       "file_object");
    chk(fmt.issuing_thread_id == get.issuing_thread_id, "issuing_thread_id");
    chk(fmt.create_options    == get.create_options,    "create_options");
    chk(fmt.create_attributes == get.create_attributes, "create_attributes");
    chk(fmt.share_access      == get.share_access,      "share_access");
    chk(fmt.file_name         == get.file_name,         "file_name");

#ifdef HAVE_KRABSETW
    krabs::schema_locator locator;
    auto krabs_r = parse_file_krabsetw(locator, record);
    chk(fmt.irp               == krabs_r.irp,               "irp (krabsetw)");
    chk(fmt.file_object       == krabs_r.file_object,       "file_object (krabsetw)");
    chk(fmt.issuing_thread_id == krabs_r.issuing_thread_id, "issuing_thread_id (krabsetw)");
    chk(fmt.create_options    == krabs_r.create_options,    "create_options (krabsetw)");
    chk(fmt.create_attributes == krabs_r.create_attributes, "create_attributes (krabsetw)");
    chk(fmt.share_access      == krabs_r.share_access,      "share_access (krabsetw)");
    chk(fmt.file_name         == krabs_r.file_name,         "file_name (krabsetw)");
#endif

    if (!ok) std::terminate();
    std::cout << "Pre-flight [File]:    TdhFormatProperty == TdhGetProperty"
#ifdef HAVE_KRABSETW
              << " == krabsetw"
#endif
              << " [OK]\n";
}

void verify_registry_parsers_agree(const std::vector<etw_capture::CapturedEvent>& events) {
    if (events.empty()) return;
    auto record = events[0].as_event_record();
    auto schema = get_tdh_schema(&record);
    if (schema.empty()) { std::cerr << "verify_registry: could not get schema\n"; return; }

    auto fmt = parse_registry_tdh_format(schema, record);
    auto get = parse_registry_tdh_get(schema, record);

    bool ok = true;
    auto chk = [&](bool eq, const char* field) {
        if (!eq) { std::cerr << "PREFLIGHT FAIL [Registry]: " << field << " mismatch\n"; ok = false; }
    };

    chk(fmt.base_object   == get.base_object,   "base_object");
    chk(fmt.key_object    == get.key_object,     "key_object");
    chk(fmt.status        == get.status,         "status");
    chk(fmt.disposition   == get.disposition,    "disposition");
    chk(fmt.base_name     == get.base_name,      "base_name");
    chk(fmt.relative_name == get.relative_name,  "relative_name");

#ifdef HAVE_KRABSETW
    krabs::schema_locator locator;
    auto krabs_r = parse_registry_krabsetw(locator, record);
    chk(fmt.base_object   == krabs_r.base_object,   "base_object (krabsetw)");
    chk(fmt.key_object    == krabs_r.key_object,    "key_object (krabsetw)");
    chk(fmt.status        == krabs_r.status,        "status (krabsetw)");
    chk(fmt.disposition   == krabs_r.disposition,   "disposition (krabsetw)");
    chk(fmt.base_name     == krabs_r.base_name,     "base_name (krabsetw)");
    chk(fmt.relative_name == krabs_r.relative_name, "relative_name (krabsetw)");
#endif

    if (!ok) std::terminate();
    std::cout << "Pre-flight [Registry]:TdhFormatProperty == TdhGetProperty"
#ifdef HAVE_KRABSETW
              << " == krabsetw"
#endif
              << " [OK]\n";
}

void verify_rpc_parsers_agree(const std::vector<etw_capture::CapturedEvent>& events) {
    if (events.empty()) return;
    auto record = events[0].as_event_record();
    auto schema = get_tdh_schema(&record);
    if (schema.empty()) { std::cerr << "verify_rpc: could not get schema\n"; return; }

    auto fmt = parse_rpc_tdh_format(schema, record);
    auto get = parse_rpc_tdh_get(schema, record);

    bool ok = true;
    auto chk = [&](bool eq, const char* field) {
        if (!eq) { std::cerr << "PREFLIGHT FAIL [RPC]: " << field << " mismatch\n"; ok = false; }
    };

    chk(fmt.interface_uuid        == get.interface_uuid,        "interface_uuid");
    chk(fmt.proc_num              == get.proc_num,              "proc_num");
    chk(fmt.protocol              == get.protocol,              "protocol");
    chk(fmt.network_address       == get.network_address,       "network_address");
    chk(fmt.endpoint              == get.endpoint,              "endpoint");
    chk(fmt.options               == get.options,               "options");
    chk(fmt.authentication_level  == get.authentication_level,  "authentication_level");
    chk(fmt.authentication_service== get.authentication_service,"authentication_service");
    chk(fmt.impersonation_level   == get.impersonation_level,   "impersonation_level");

#ifdef HAVE_KRABSETW
    krabs::schema_locator locator;
    auto krabs_r = parse_rpc_krabsetw(locator, record);
    chk(fmt.interface_uuid         == krabs_r.interface_uuid,         "interface_uuid (krabsetw)");
    chk(fmt.proc_num               == krabs_r.proc_num,               "proc_num (krabsetw)");
    chk(fmt.protocol               == krabs_r.protocol,               "protocol (krabsetw)");
    chk(fmt.network_address        == krabs_r.network_address,        "network_address (krabsetw)");
    chk(fmt.endpoint               == krabs_r.endpoint,               "endpoint (krabsetw)");
    chk(fmt.options                == krabs_r.options,                "options (krabsetw)");
    chk(fmt.authentication_level   == krabs_r.authentication_level,   "authentication_level (krabsetw)");
    chk(fmt.authentication_service == krabs_r.authentication_service, "authentication_service (krabsetw)");
    chk(fmt.impersonation_level    == krabs_r.impersonation_level,    "impersonation_level (krabsetw)");
#endif

    if (!ok) std::terminate();
    std::cout << "Pre-flight [RPC]:     TdhFormatProperty == TdhGetProperty"
#ifdef HAVE_KRABSETW
              << " == krabsetw"
#endif
              << " [OK]\n";
}

// Verify that the naive parser (all TdhFormatProperty) agrees with the typed
// parser (TdhFormatProperty for strings only) on the first captured event.
// Integer fields: convert the wstring back to an integer using wcstoul/wcstoull
// with base 0 so that both decimal ("123") and hex ("0x7B") representations work.
// String/SID fields: direct wstring comparison (both parsers use TdhFormatProperty).
// create_time: formatted as a datetime string by TdhFormatProperty — just verify
// it is non-empty since round-tripping a FILETIME through a datetime string is lossy.

void verify_process_naive_agrees(const std::vector<etw_capture::CapturedEvent>& events) {
    if (events.empty()) return;
    auto record = events[0].as_event_record();
    auto schema = get_tdh_schema(&record);
    if (schema.empty()) { std::cerr << "verify_process_naive: could not get schema\n"; return; }

    auto fmt   = parse_process_tdh_format(schema, record);
    auto naive = parse_process_tdh_fmt_naive(schema, record);

    bool ok = true;
    auto chk = [&](bool eq, const char* field) {
        if (!eq) { std::cerr << "PREFLIGHT FAIL [Process/Naive]: " << field << " mismatch\n"; ok = false; }
    };
    auto to_u32 = [](const std::wstring& s) { return static_cast<uint32_t>(wcstoul(s.c_str(), nullptr, 0)); };
    auto to_u64 = [](const std::wstring& s) { return wcstoull(s.c_str(), nullptr, 0); };

    chk(fmt.process_id == to_u32(naive.process_id), "process_id");
    chk(fmt.process_sequence_number == to_u64(naive.process_sequence_number), "process_sequence_number");
    chk(!naive.create_time.empty(), "create_time (non-empty)"); // FILETIME formatted as datetime — skip numeric check
    chk(fmt.parent_process_id == to_u32(naive.parent_process_id), "parent_process_id");
    chk(fmt.parent_process_sequence_number == to_u64(naive.parent_process_sequence_number), "parent_process_sequence_number");
    chk(fmt.session_id == to_u32(naive.session_id), "session_id");
    chk(fmt.flags == to_u32(naive.flags), "flags");
    chk(fmt.process_token_elevation_type == to_u32(naive.process_token_elevation_type), "process_token_elevation_type");
    chk(fmt.process_token_is_elevated == to_u32(naive.process_token_is_elevated), "process_token_is_elevated");
    chk(fmt.mandatory_label == naive.mandatory_label, "mandatory_label");       // both use TdhFormatProperty
    chk(fmt.image_name == naive.image_name, "image_name");
    chk(fmt.image_checksum == to_u32(naive.image_checksum), "image_checksum");
    chk(fmt.time_date_stamp == to_u32(naive.time_date_stamp), "time_date_stamp");
    chk(fmt.package_full_name == naive.package_full_name, "package_full_name");
    chk(fmt.package_relative_app_id == naive.package_relative_app_id, "package_relative_app_id");
    chk(fmt.security_mitigations == to_u32(naive.security_mitigations), "security_mitigations");

    if (!ok) std::terminate();
    std::cout << "Pre-flight [Process/Naive]: TdhFmtProp (naive) agrees with TdhFormatProperty [OK]\n";
}

void verify_thread_naive_agrees(const std::vector<etw_capture::CapturedEvent>& events) {
    if (events.empty()) return;
    auto record = events[0].as_event_record();
    auto schema = get_tdh_schema(&record);
    if (schema.empty()) { std::cerr << "verify_thread_naive: could not get schema\n"; return; }

    auto fmt   = parse_thread_tdh_format(schema, record);
    auto naive = parse_thread_tdh_fmt_naive(schema, record);

    bool ok = true;
    auto chk = [&](bool eq, const char* field) {
        if (!eq) { std::cerr << "PREFLIGHT FAIL [Thread/Naive]: " << field << " mismatch\n"; ok = false; }
    };
    auto to_u32 = [](const std::wstring& s) { return static_cast<uint32_t>(wcstoul(s.c_str(), nullptr, 0)); };
    auto to_u64 = [](const std::wstring& s) { return wcstoull(s.c_str(), nullptr, 0); };

    chk(fmt.process_id       == to_u32(naive.process_id),       "process_id");
    chk(fmt.thread_id        == to_u32(naive.thread_id),        "thread_id");
    chk(fmt.stack_base       == to_u64(naive.stack_base),       "stack_base");
    chk(fmt.stack_limit      == to_u64(naive.stack_limit),      "stack_limit");
    chk(fmt.user_stack_base  == to_u64(naive.user_stack_base),  "user_stack_base");
    chk(fmt.user_stack_limit == to_u64(naive.user_stack_limit), "user_stack_limit");
    chk(fmt.start_addr       == to_u64(naive.start_addr),       "start_addr");
    chk(fmt.win32_start_addr == to_u64(naive.win32_start_addr), "win32_start_addr");
    chk(fmt.teb_base         == to_u64(naive.teb_base),         "teb_base");
    chk(fmt.sub_process_tag  == to_u32(naive.sub_process_tag),  "sub_process_tag");

    if (!ok) std::terminate();
    std::cout << "Pre-flight [Thread/Naive]:  TdhFmtProp (naive) agrees with TdhFormatProperty [OK]\n";
}

void verify_file_naive_agrees(const std::vector<etw_capture::CapturedEvent>& events) {
    if (events.empty()) return;
    auto record = events[0].as_event_record();
    auto schema = get_tdh_schema(&record);
    if (schema.empty()) { std::cerr << "verify_file_naive: could not get schema\n"; return; }

    auto fmt   = parse_file_tdh_format(schema, record);
    auto naive = parse_file_tdh_fmt_naive(schema, record);

    bool ok = true;
    auto chk = [&](bool eq, const char* field) {
        if (!eq) { std::cerr << "PREFLIGHT FAIL [File/Naive]: " << field << " mismatch\n"; ok = false; }
    };
    auto to_u32 = [](const std::wstring& s) { return static_cast<uint32_t>(wcstoul(s.c_str(), nullptr, 0)); };
    auto to_u64 = [](const std::wstring& s) { return wcstoull(s.c_str(), nullptr, 0); };

    chk(fmt.irp               == to_u64(naive.irp),               "irp");
    chk(fmt.file_object       == to_u64(naive.file_object),       "file_object");
    chk(fmt.issuing_thread_id == to_u32(naive.issuing_thread_id), "issuing_thread_id");
    chk(fmt.create_options    == to_u32(naive.create_options),    "create_options");
    chk(fmt.create_attributes == to_u32(naive.create_attributes), "create_attributes");
    chk(fmt.share_access      == to_u32(naive.share_access),      "share_access");
    chk(fmt.file_name         == naive.file_name,                  "file_name");

    if (!ok) std::terminate();
    std::cout << "Pre-flight [File/Naive]:    TdhFmtProp (naive) agrees with TdhFormatProperty [OK]\n";
}

void verify_registry_naive_agrees(const std::vector<etw_capture::CapturedEvent>& events) {
    if (events.empty()) return;
    auto record = events[0].as_event_record();
    auto schema = get_tdh_schema(&record);
    if (schema.empty()) { std::cerr << "verify_registry_naive: could not get schema\n"; return; }

    auto fmt   = parse_registry_tdh_format(schema, record);
    auto naive = parse_registry_tdh_fmt_naive(schema, record);

    bool ok = true;
    auto chk = [&](bool eq, const char* field) {
        if (!eq) { std::cerr << "PREFLIGHT FAIL [Registry/Naive]: " << field << " mismatch\n"; ok = false; }
    };
    auto to_u32 = [](const std::wstring& s) { return static_cast<uint32_t>(wcstoul(s.c_str(), nullptr, 0)); };
    auto to_u64 = [](const std::wstring& s) { return wcstoull(s.c_str(), nullptr, 0); };

    chk(fmt.base_object   == to_u64(naive.base_object),   "base_object");
    chk(fmt.key_object    == to_u64(naive.key_object),     "key_object");
    chk(fmt.status        == to_u32(naive.status),         "status");
    chk(fmt.disposition   == to_u32(naive.disposition),    "disposition");
    chk(fmt.base_name     == naive.base_name,               "base_name");
    chk(fmt.relative_name == naive.relative_name,           "relative_name");

    if (!ok) std::terminate();
    std::cout << "Pre-flight [Registry/Naive]:TdhFmtProp (naive) agrees with TdhFormatProperty [OK]\n";
}

void verify_rpc_naive_agrees(const std::vector<etw_capture::CapturedEvent>& events) {
    if (events.empty()) return;
    auto record = events[0].as_event_record();
    auto schema = get_tdh_schema(&record);
    if (schema.empty()) { std::cerr << "verify_rpc_naive: could not get schema\n"; return; }

    auto fmt   = parse_rpc_tdh_format(schema, record);
    auto naive = parse_rpc_tdh_fmt_naive(schema, record);

    bool ok = true;
    auto chk = [&](bool eq, const char* field) {
        if (!eq) { std::cerr << "PREFLIGHT FAIL [RPC/Naive]: " << field << " mismatch\n"; ok = false; }
    };
    auto to_u32 = [](const std::wstring& s) { return static_cast<uint32_t>(wcstoul(s.c_str(), nullptr, 0)); };

    // GUID: format the typed GUID as L"{...}" and compare against naive's TdhFormatProperty output.
    {
        wchar_t guid_str[64];
        swprintf_s(guid_str, 64,
            L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            fmt.interface_uuid.Data1, fmt.interface_uuid.Data2, fmt.interface_uuid.Data3,
            fmt.interface_uuid.Data4[0], fmt.interface_uuid.Data4[1],
            fmt.interface_uuid.Data4[2], fmt.interface_uuid.Data4[3], fmt.interface_uuid.Data4[4],
            fmt.interface_uuid.Data4[5], fmt.interface_uuid.Data4[6], fmt.interface_uuid.Data4[7]);
        chk(_wcsicmp(naive.interface_uuid.c_str(), guid_str) == 0, "interface_uuid");
    }

    chk(fmt.proc_num               == to_u32(naive.proc_num),               "proc_num");
    chk(fmt.protocol               == to_u32(naive.protocol),               "protocol");
    chk(fmt.network_address        == naive.network_address,                 "network_address");
    chk(fmt.endpoint               == naive.endpoint,                        "endpoint");
    chk(fmt.options                == naive.options,                         "options");
    chk(fmt.authentication_level   == to_u32(naive.authentication_level),   "authentication_level");
    chk(fmt.authentication_service == to_u32(naive.authentication_service), "authentication_service");
    chk(fmt.impersonation_level    == to_u32(naive.impersonation_level),    "impersonation_level");

    if (!ok) std::terminate();
    std::cout << "Pre-flight [RPC/Naive]:     TdhFmtProp (naive) agrees with TdhFormatProperty [OK]\n";
}

// =============================================================================
// Main Benchmark Runner
// =============================================================================

void benchmark_process_events(const std::string& filename) {
    std::cout << "Loading " << filename << "...\n";
    auto reader = etw_capture::EventFileReader(filename);
    auto events = reader.read_all();
    std::cout << "Loaded " << events.size() << " events\n";

    if (events.empty()) {
        std::cout << "No events to benchmark!\n";
        return;
    }

    std::vector<BenchmarkResult> results;

    // Schema loaded once for diagnostic output only (outside the timed region)
    auto first_record = events[0].as_event_record();
    auto diag_schema = get_tdh_schema(&first_record);
    print_event_name(diag_schema);

    // Pre-flight: verify all implementations agree on the first event
    verify_process_parsers_agree(events);
    verify_process_naive_agrees(events);

    // Benchmark TdhFormatProperty — schema lookup is part of the cost
    std::cout << "Benchmarking TdhFormatProperty...\n";
    results.push_back(benchmark_parser(
        "TdhFormatProperty",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_process_tdh_format(schema, record);
        }
    ));

    // The same parse with the schema resolved once instead of per event. A schema
    // cache is krabsetw's 2016 contribution, inherited by etw-rs, so measuring TDH
    // both ways separates what the cache buys from what the rest of a parser buys.
    //
    // The cache is keyed and consulted on every event, exactly as krabsetw's and
    // etw-rs's are, so the lookup is priced in. Resolving the schema once outside the
    // loop would measure a best case no consumer gets.
    SchemaCache schema_cache;
    std::cout << "Benchmarking TdhFormatProperty (cached)...\n";
    results.push_back(benchmark_parser(
        "TdhFmtProp (cached)",
        events,
        [&schema_cache](const EVENT_RECORD& record) {
            return parse_process_tdh_format(schema_cache.get(record), record);
        }
    ));

    std::cout << "Benchmarking TdhFormatProperty (naive)...\n";
    results.push_back(benchmark_parser(
        "TdhFmtProp (naive)",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_process_tdh_fmt_naive(schema, record);
        }
    ));

    // Benchmark TdhGetProperty
    std::cout << "Benchmarking TdhGetProperty...\n";
    results.push_back(benchmark_parser(
        "TdhGetProperty",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_process_tdh_get(schema, record);
        }
    ));

#ifdef HAVE_KRABSETW
    // Benchmark krabsetw with schema_locator (proper caching)
    std::cout << "Benchmarking krabsetw...\n";
    krabs::schema_locator locator;
    results.push_back(benchmark_parser(
        "krabsetw",
        events,
        [&locator](const EVENT_RECORD& record) {
            return parse_process_krabsetw(locator, record);
        }
    ));

    // Profile krabsetw to break down timing
    std::cout << "\nProfiling krabsetw for Process events...\n";
    TimingBreakdown process_timing = profile_parser(
        events,
        [&locator](const EVENT_RECORD& record) {
            return parse_process_krabsetw_profiled(locator, record);
        }
    );
    process_timing.print("krabsetw Process");
#endif

    print_results(results);
}

void benchmark_thread_events(const std::string& filename) {
    std::cout << "Loading " << filename << "...\n";
    auto reader = etw_capture::EventFileReader(filename);
    auto events = reader.read_all();
    std::cout << "Loaded " << events.size() << " events\n";

    if (events.empty()) {
        std::cout << "No events to benchmark!\n";
        return;
    }

    std::vector<BenchmarkResult> results;

    auto first_record = events[0].as_event_record();
    auto diag_schema = get_tdh_schema(&first_record);
    print_event_name(diag_schema);

    verify_thread_parsers_agree(events);
    verify_thread_naive_agrees(events);

    std::cout << "Benchmarking TdhFormatProperty...\n";
    results.push_back(benchmark_parser(
        "TdhFormatProperty",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_thread_tdh_format(schema, record);
        }
    ));

    // The same parse with the schema resolved once instead of per event. A schema
    // cache is krabsetw's 2016 contribution, inherited by etw-rs, so measuring TDH
    // both ways separates what the cache buys from what the rest of a parser buys.
    //
    // The cache is keyed and consulted on every event, exactly as krabsetw's and
    // etw-rs's are, so the lookup is priced in. Resolving the schema once outside the
    // loop would measure a best case no consumer gets.
    SchemaCache schema_cache;
    std::cout << "Benchmarking TdhFormatProperty (cached)...\n";
    results.push_back(benchmark_parser(
        "TdhFmtProp (cached)",
        events,
        [&schema_cache](const EVENT_RECORD& record) {
            return parse_thread_tdh_format(schema_cache.get(record), record);
        }
    ));

    std::cout << "Benchmarking TdhFormatProperty (naive)...\n";
    results.push_back(benchmark_parser(
        "TdhFmtProp (naive)",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_thread_tdh_fmt_naive(schema, record);
        }
    ));

    std::cout << "Benchmarking TdhGetProperty...\n";
    results.push_back(benchmark_parser(
        "TdhGetProperty",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_thread_tdh_get(schema, record);
        }
    ));

#ifdef HAVE_KRABSETW
    std::cout << "Benchmarking krabsetw...\n";
    krabs::schema_locator locator;
    results.push_back(benchmark_parser(
        "krabsetw",
        events,
        [&locator](const EVENT_RECORD& record) {
            return parse_thread_krabsetw(locator, record);
        }
    ));
#endif

    print_results(results);
}

void benchmark_file_events(const std::string& filename) {
    std::cout << "Loading " << filename << "...\n";
    auto reader = etw_capture::EventFileReader(filename);
    auto events = reader.read_all();
    std::cout << "Loaded " << events.size() << " events\n";

    if (events.empty()) {
        std::cout << "No events to benchmark!\n";
        return;
    }

    std::vector<BenchmarkResult> results;

    auto first_record = events[0].as_event_record();
    auto diag_schema = get_tdh_schema(&first_record);
    print_event_name(diag_schema);

    verify_file_parsers_agree(events);
    verify_file_naive_agrees(events);

    std::cout << "Benchmarking TdhFormatProperty...\n";
    results.push_back(benchmark_parser(
        "TdhFormatProperty",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_file_tdh_format(schema, record);
        }
    ));

    // The same parse with the schema resolved once instead of per event. A schema
    // cache is krabsetw's 2016 contribution, inherited by etw-rs, so measuring TDH
    // both ways separates what the cache buys from what the rest of a parser buys.
    //
    // The cache is keyed and consulted on every event, exactly as krabsetw's and
    // etw-rs's are, so the lookup is priced in. Resolving the schema once outside the
    // loop would measure a best case no consumer gets.
    SchemaCache schema_cache;
    std::cout << "Benchmarking TdhFormatProperty (cached)...\n";
    results.push_back(benchmark_parser(
        "TdhFmtProp (cached)",
        events,
        [&schema_cache](const EVENT_RECORD& record) {
            return parse_file_tdh_format(schema_cache.get(record), record);
        }
    ));

    std::cout << "Benchmarking TdhFormatProperty (naive)...\n";
    results.push_back(benchmark_parser(
        "TdhFmtProp (naive)",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_file_tdh_fmt_naive(schema, record);
        }
    ));

    std::cout << "Benchmarking TdhGetProperty...\n";
    results.push_back(benchmark_parser(
        "TdhGetProperty",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_file_tdh_get(schema, record);
        }
    ));

#ifdef HAVE_KRABSETW
    std::cout << "Benchmarking krabsetw...\n";
    krabs::schema_locator locator;
    results.push_back(benchmark_parser(
        "krabsetw",
        events,
        [&locator](const EVENT_RECORD& record) {
            return parse_file_krabsetw(locator, record);
        }
    ));
#endif

    print_results(results);
}

void benchmark_registry_events(const std::string& filename) {
    std::cout << "Loading " << filename << "...\n";
    auto reader = etw_capture::EventFileReader(filename);
    auto events = reader.read_all();
    std::cout << "Loaded " << events.size() << " events\n";

    if (events.empty()) {
        std::cout << "No events to benchmark!\n";
        return;
    }

    std::vector<BenchmarkResult> results;

    auto first_record = events[0].as_event_record();
    auto diag_schema = get_tdh_schema(&first_record);
    print_event_name(diag_schema);

    verify_registry_parsers_agree(events);
    verify_registry_naive_agrees(events);

    std::cout << "Benchmarking TdhFormatProperty...\n";
    results.push_back(benchmark_parser(
        "TdhFormatProperty",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_registry_tdh_format(schema, record);
        }
    ));

    // The same parse with the schema resolved once instead of per event. A schema
    // cache is krabsetw's 2016 contribution, inherited by etw-rs, so measuring TDH
    // both ways separates what the cache buys from what the rest of a parser buys.
    //
    // The cache is keyed and consulted on every event, exactly as krabsetw's and
    // etw-rs's are, so the lookup is priced in. Resolving the schema once outside the
    // loop would measure a best case no consumer gets.
    SchemaCache schema_cache;
    std::cout << "Benchmarking TdhFormatProperty (cached)...\n";
    results.push_back(benchmark_parser(
        "TdhFmtProp (cached)",
        events,
        [&schema_cache](const EVENT_RECORD& record) {
            return parse_registry_tdh_format(schema_cache.get(record), record);
        }
    ));

    std::cout << "Benchmarking TdhFormatProperty (naive)...\n";
    results.push_back(benchmark_parser(
        "TdhFmtProp (naive)",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_registry_tdh_fmt_naive(schema, record);
        }
    ));

    std::cout << "Benchmarking TdhGetProperty...\n";
    results.push_back(benchmark_parser(
        "TdhGetProperty",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_registry_tdh_get(schema, record);
        }
    ));

#ifdef HAVE_KRABSETW
    std::cout << "Benchmarking krabsetw...\n";
    krabs::schema_locator locator;
    results.push_back(benchmark_parser(
        "krabsetw",
        events,
        [&locator](const EVENT_RECORD& record) {
            return parse_registry_krabsetw(locator, record);
        }
    ));
#endif

    print_results(results);
}

void benchmark_rpc_events(const std::string& filename) {
    std::cout << "Loading " << filename << "...\n";
    auto reader = etw_capture::EventFileReader(filename);
    auto events = reader.read_all();
    std::cout << "Loaded " << events.size() << " events\n";

    if (events.empty()) {
        std::cout << "No events to benchmark!\n";
        return;
    }

    std::vector<BenchmarkResult> results;

    auto first_record = events[0].as_event_record();
    auto diag_schema = get_tdh_schema(&first_record);
    print_event_name(diag_schema);

    verify_rpc_parsers_agree(events);
    verify_rpc_naive_agrees(events);

    std::cout << "Benchmarking TdhFormatProperty...\n";
    results.push_back(benchmark_parser(
        "TdhFormatProperty",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_rpc_tdh_format(schema, record);
        }
    ));

    // The same parse with the schema resolved once instead of per event. A schema
    // cache is krabsetw's 2016 contribution, inherited by etw-rs, so measuring TDH
    // both ways separates what the cache buys from what the rest of a parser buys.
    //
    // The cache is keyed and consulted on every event, exactly as krabsetw's and
    // etw-rs's are, so the lookup is priced in. Resolving the schema once outside the
    // loop would measure a best case no consumer gets.
    SchemaCache schema_cache;
    std::cout << "Benchmarking TdhFormatProperty (cached)...\n";
    results.push_back(benchmark_parser(
        "TdhFmtProp (cached)",
        events,
        [&schema_cache](const EVENT_RECORD& record) {
            return parse_rpc_tdh_format(schema_cache.get(record), record);
        }
    ));

    std::cout << "Benchmarking TdhFormatProperty (naive)...\n";
    results.push_back(benchmark_parser(
        "TdhFmtProp (naive)",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_rpc_tdh_fmt_naive(schema, record);
        }
    ));

    std::cout << "Benchmarking TdhGetProperty...\n";
    results.push_back(benchmark_parser(
        "TdhGetProperty",
        events,
        [](const EVENT_RECORD& record) {
            auto schema = get_tdh_schema(&record);
            return parse_rpc_tdh_get(schema, record);
        }
    ));

#ifdef HAVE_KRABSETW
    std::cout << "Benchmarking krabsetw...\n";
    krabs::schema_locator locator;
    results.push_back(benchmark_parser(
        "krabsetw",
        events,
        [&locator](const EVENT_RECORD& record) {
            return parse_rpc_krabsetw(locator, record);
        }
    ));
    // Profile krabsetw to break down timing
    std::cout << "\nProfiling krabsetw for RPC events...\n";
    TimingBreakdown rpc_timing = profile_parser(
        events,
        [&locator](const EVENT_RECORD& record) {
            return parse_rpc_krabsetw_profiled(locator, record);
        }
    );
    rpc_timing.print("krabsetw RPC");
#endif

    print_results(results);
}

int main(int argc, char* argv[]) {
    pin_to_performance_cores();

    try {
        std::string filename = "captured_process_events.bin";

        if (argc > 1) {
            filename = argv[1];
        }

        std::cout << "ETW Parser Benchmarks - C++ Edition\n";
        std::cout << "====================================\n\n";

#ifndef HAVE_KRABSETW
        std::cout << "NOTE: krabsetw not available. Define HAVE_KRABSETW and link krabsetw to enable.\n\n";
#endif

        // Dispatch to appropriate benchmark based on filename
        if (filename.find("process") != std::string::npos) {
            benchmark_process_events(filename);
        } else if (filename.find("thread") != std::string::npos) {
            benchmark_thread_events(filename);
        } else if (filename.find("file") != std::string::npos) {
            benchmark_file_events(filename);
        } else if (filename.find("registry") != std::string::npos) {
            benchmark_registry_events(filename);
        } else if (filename.find("rpc") != std::string::npos) {
            benchmark_rpc_events(filename);
        } else {
            std::cerr << "Unknown event type for file: " << filename << "\n";
            std::cerr << "Supported files: *process*, *thread*, *file*, *registry*, *rpc*\n";
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
