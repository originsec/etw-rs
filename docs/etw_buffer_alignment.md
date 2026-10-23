# ETW Buffer Alignment Analysis

Reverse-engineered from `ntoskrnl.exe` (26100.6725) and `sechost.dll` (26100)
on Windows 11 via Ghidra. February 2026.

## Summary

**`EVENT_RECORD.UserData` is guaranteed 8-byte aligned** for all modern
(manifest-based) events and all system logger events. The only exception
is legacy WPP trace messages (marker `0x9000xxxx`), which have a variable-length
header that can produce non-8-byte-aligned UserData offsets.

**16-byte alignment is NOT guaranteed.** Roughly 50% of events happen to be
16-byte aligned due to arithmetic coincidence, but this must not be relied upon.

## Producer Side (ntoskrnl)

### Buffer Allocation

ETW buffers are allocated via `ExAllocatePool2` (at least 16-byte aligned on
x64) or `MmMapLockedPagesSpecifyCache` (page-aligned). Every buffer starts with
a `WMI_BUFFER_HEADER` of 0x48 (72) bytes. The first event entry starts at
buffer + 0x48.

### Entry Reservation

All event writes go through `EtwpReserveTraceBuffer`, which rounds every entry
size up to an 8-byte boundary:

```c
alignedSize = (eventSize + 7) & ~7;  // 8-byte align
```

The function uses interlocked compare-and-swap on the buffer's `CurrentOffset`
field to advance the write position atomically. The returned pointer is always
8-byte aligned relative to the buffer base.

### Entry Header Formats

The kernel uses several entry header formats, all with sizes that are multiples
of 8. The header format determines where UserData starts within each entry:

| Format | Marker | Header Size | UserData Offset |
|--------|--------|-------------|-----------------|
| PERFINFO_TRACE_ENTRY | `0xC011xxxx` | 16 (0x10) | +0x10 |
| COMPACT_TRACE_ENTRY | `0xC004xxxx` | 24 (0x18) | +0x18 |
| SYSTEM_TRACE_ENTRY | `0xC002xxxx` | 32 (0x20) | +0x20 |
| EVENT_HEADER | `0xC013xxxx` | 80 (0x50) | +0x50, plus any extended data items |
| MESSAGE_TRACE_HEADER | `0x9000xxxx` | Variable (8+) | Variable |

Since entries start at 8-byte boundaries, the non-WPP headers above are multiples
of 8, and extended data item sizes are too (see below), UserData is always 8-byte
aligned for events using those formats.

#### Header Format Selection (`EtwpLogKernelEvent`)

For kernel system logger events, the header format is selected by per-event flags:

| Bit | Meaning | Result |
|-----|---------|--------|
| bit 8 = 0 | No ThreadId/ProcessId needed | PERFINFO (16B) |
| bit 8 = 1, bit 28 = 0 | TID/PID + CPU times | SYSTEM_TRACE (32B) |
| bit 8 = 1, bit 28 = 1 | TID/PID, no CPU times | COMPACT (24B) |

Examination of all 71 callers of `EtwpLogKernelEvent` on Windows 11 26100 found
**no caller that sets bit 28**. COMPACT_TRACE_ENTRY appears to be dead code. In
practice, all kernel system logger events use either PERFINFO or SYSTEM_TRACE.

#### WPP Messages (MESSAGE_TRACE_HEADER)

WPP trace messages have a variable-length header depending on which optional
fields (sequence number, GUID, timestamp, system info) are present. This can
produce non-8-byte-aligned UserData offsets (e.g., sequence-only = 12 bytes).

## Consumer Side (sechost.dll)

### Zero-Copy UserData

`EVENT_RECORD.UserData` is a **direct pointer into the kernel ETW buffer** — no
allocation or memcpy occurs. The consumer function `EtwpMapEventToEventRecord`
sets:

```
EVENT_RECORD.UserData = bufferEntry + headerSize
```

The pointer inherits its alignment from the buffer's entry reservation mechanism
combined with the fixed header sizes.

### Buffer Walking

`EtwpLoadEventTrigger` walks each buffer starting at offset 0x48 (after
`WMI_BUFFER_HEADER`). Entry advancement is also 8-byte aligned:

```c
nextOffset = (entrySize + 7) & ~7;  // 8-byte align
```

This matches the kernel-side reservation, confirming alignment is preserved
end-to-end.

### Extended Data Items

For EVENT_HEADER entries, extended data items may follow the 80-byte header
before UserData. These are also direct buffer pointers. The consumer rejects an
entry whose item size is not a multiple of 8 (`(size & 7) != 0`). That checks
sizes, not pointers: alignment follows because the first item starts 8-aligned
after the 80-byte header and each item's size keeps the next one 8-aligned —
including UserData after the last item.

## 16-Byte Alignment Analysis

UserData is **guaranteed 8-byte aligned but NOT 16-byte aligned**.

### Why Not 16-Byte

The chain of offsets from buffer base to UserData:

```
Buffer base:           16-byte aligned (pool allocator)
WMI_BUFFER_HEADER:     0x48 bytes = 72 = 64 + 8  →  offset ≡ 8 (mod 16)
First entry starts at: base + 0x48                →  ≡ 8 (mod 16)
```

For the first entry, adding the header size gives (EVENT_HEADER assumes no
extended data items):

| Header | Entry base (mod 16) | + header | UserData (mod 16) |
|--------|---------------------|----------|--------------------|
| PERFINFO (0x10) | 8 | +16 | **8** |
| SYSTEM_TRACE (0x20) | 8 | +32 | **8** |
| EVENT_HEADER (0x50) | 8 | +80 | **8** |

Without extended data, the first event's UserData is 8-but-NOT-16-byte aligned.
Extended data item sizes are multiples of 8 but need not be multiples of 16, so
they can flip the mod-16 result.

### Subsequent Events

Each entry is padded to 8 bytes. If the padded entry size is ≡ 0 (mod 16), the
next entry has the same mod-16 alignment. If ≡ 8 (mod 16), it flips. Since
event payloads vary, entries alternate unpredictably between the two alignments.

**Result:** ~50% of UserData pointers happen to be 16-byte aligned. Code that
requires >8-byte alignment must copy the data or use unaligned instructions.

## Implications for etw-rs

1. **Safe to assume 8-byte aligned UserData** for manifest-based and system
   logger events. Confirmed on both producer (ntoskrnl) and consumer (sechost.dll)
   sides. Classic `TraceEvent` headers (`EVENT_TRACE_HEADER`,
   `EVENT_INSTANCE_HEADER`) were not analysed. `tests/userdata_alignment.rs`
   checks this at runtime for kernel and manifest events and for `STACK_TRACE64`
   extended data.

2. **Do NOT assume 16-byte alignment.** Only ~50% of events are 16-byte aligned.
   Use unaligned reads or memcpy for types requiring >8-byte alignment.

3. **UserData is a zero-copy direct pointer into the ETW buffer.** The pointer
   inherits 8-byte alignment from the buffer's entry reservation mechanism
   combined with 8-byte-multiple header sizes.

4. **COMPACT_TRACE_ENTRY is dead code** on Windows 11 26100. All kernel system
   logger events use either PERFINFO (16B) or SYSTEM_TRACE (32B). The consumer
   still handles COMPACT for backwards compatibility.

5. **Classic WPP events** may have non-8-byte-aligned UserData, including
   through the `EventRecordCallback` path. UserData is the same zero-copy
   `bufferEntry + headerSize` pointer (point 3), so the WPP header's variable
   length reaches the callback unchanged.

6. **Extended data items** are also zero-copy buffer pointers. They are 8-byte
   aligned because the consumer validates that their sizes are multiples of 8.
