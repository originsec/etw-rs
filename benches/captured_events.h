// C++ Header for Reading Captured ETW Events
// Binary format produced by live_events.rs benchmark
//
// To capture events (Administrator on the first run; later runs reuse the files):
//   cargo bench --bench live_events
//
// This writes captured_process_events.bin, captured_thread_events.bin, etc. to the
// repository root.

#pragma once
#include <vector>
#include <string>
#include <fstream>
#include <cstdint>
#include <memory>
#include <windows.h>   // Must be included before other Windows headers
#include <evntcons.h>  // For EVENT_RECORD, EVENT_HEADER

namespace etw_capture {

// File format:
// - magic: "ETWCAP01" (8 bytes)
// - event_count: uint64_t (little-endian)
// - For each event:
//   - total_size: uint32_t (size of this event record including this field)
//   - record_blob_len: uint32_t
//   - record_blob: [uint8_t; record_blob_len] (contains EVENT_HEADER at start)
//   - user_data_offset: uint64_t (offset within record_blob where UserData starts)
//   - user_data_len: uint64_t (length of UserData)

struct CapturedEvent {
    std::vector<uint8_t> record_blob;
    uint64_t user_data_offset;
    uint64_t user_data_len;

    // Reconstruct an EVENT_RECORD for parsing
    // WARNING: The returned EVENT_RECORD contains pointers into record_blob
    // The CapturedEvent must remain alive while using the EVENT_RECORD
    EVENT_RECORD as_event_record() const {
        EVENT_RECORD record = {};

        if (record_blob.size() >= sizeof(EVENT_HEADER)) {
            // Copy EVENT_HEADER from blob
            memcpy(&record.EventHeader, record_blob.data(), sizeof(EVENT_HEADER));

            // Set UserData pointer
            if (user_data_len > 0 && user_data_offset + user_data_len <= record_blob.size()) {
                record.UserData = const_cast<void*>(
                    static_cast<const void*>(record_blob.data() + user_data_offset)
                );
                record.UserDataLength = static_cast<USHORT>(user_data_len);
            }
        }

        return record;
    }
};

class EventFileReader {
private:
    std::ifstream file_;
    uint64_t event_count_ = 0;
    size_t events_read_ = 0;

public:
    explicit EventFileReader(const std::string& path) : file_(path, std::ios::binary) {
        if (!file_.is_open()) {
            throw std::runtime_error("Failed to open file: " + path);
        }

        // Read and validate magic
        char magic[8];
        file_.read(magic, 8);
        if (!file_ || memcmp(magic, "ETWCAP01", 8) != 0) {
            throw std::runtime_error("Invalid magic header");
        }

        // Read event count
        file_.read(reinterpret_cast<char*>(&event_count_), sizeof(event_count_));
        if (!file_) {
            throw std::runtime_error("Failed to read event count");
        }
    }

    uint64_t event_count() const { return event_count_; }
    size_t events_read() const { return events_read_; }
    bool has_more() const { return events_read_ < event_count_ && file_.good(); }

    // Read next event from file
    // Returns nullptr if no more events or error
    std::unique_ptr<CapturedEvent> read_next() {
        if (!has_more()) {
            return nullptr;
        }

        // Read total_size
        uint32_t total_size;
        file_.read(reinterpret_cast<char*>(&total_size), sizeof(total_size));
        if (!file_) return nullptr;

        // Read record_blob_len
        uint32_t record_blob_len;
        file_.read(reinterpret_cast<char*>(&record_blob_len), sizeof(record_blob_len));
        if (!file_) return nullptr;

        // Read record_blob
        std::vector<uint8_t> record_blob(record_blob_len);
        file_.read(reinterpret_cast<char*>(record_blob.data()), record_blob_len);
        if (!file_) return nullptr;

        // Read user_data_offset and user_data_len
        uint64_t user_data_offset, user_data_len;
        file_.read(reinterpret_cast<char*>(&user_data_offset), sizeof(user_data_offset));
        file_.read(reinterpret_cast<char*>(&user_data_len), sizeof(user_data_len));
        if (!file_) return nullptr;

        events_read_++;

        auto event = std::make_unique<CapturedEvent>();
        event->record_blob = std::move(record_blob);
        event->user_data_offset = user_data_offset;
        event->user_data_len = user_data_len;
        return event;
    }

    // Read all events from file
    std::vector<CapturedEvent> read_all() {
        std::vector<CapturedEvent> events;
        events.reserve(event_count_);

        while (auto event = read_next()) {
            events.push_back(std::move(*event));
        }

        return events;
    }
};

// Example usage:
//
// int main() {
//     auto reader = etw_capture::EventFileReader("captured_process_events.bin");
//     auto events = reader.read_all();
//
//     for (const auto& event : events) {
//         EVENT_RECORD record = event.as_event_record();
//         // Parse with krabsetw or TDH...
//     }
//
//     return 0;
// }

} // namespace etw_capture
