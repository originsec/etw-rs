//! Differential test: `Timestamp`'s pure-Rust calendar arithmetic versus the
//! `FileTimeToSystemTime` it replaced.
//!
//! `Display` used to call the Win32 conversion once per formatted timestamp. It is
//! now [Howard Hinnant's `civil_from_days`] rebased on the FILETIME epoch, so the
//! question this file answers is whether the replacement is exact.
//!
//! It can be exact, which is what makes the comparison worth running. FILETIME is
//! proleptic Gregorian with no leap seconds and no Julian cut-over, so there is no
//! range where a correct implementation is *allowed* to differ from the OS: every
//! divergence is a defect in one of the two, not a tolerance to widen. Neither side
//! shares code with the other, so they cannot agree by way of a shared misconception
//! — the flaw described in `tests/common/differential.rs`.
//!
//! Three things are compared, all through the public `Display`:
//!
//! * **the accept/reject boundary**, found by bisection rather than asserted from the
//!   documentation, since the fallback to a raw `i64` has to trigger on exactly the inputs the OS
//!   rejects;
//! * **every day from 1601 through 2600**, which is what puts a leap day on both sides of every
//!   century boundary in range — including 1700/1800/1900/2100, which are common years, and
//!   2000/2400, which are not;
//! * **100k fixed-seed pseudorandom values**, half over the whole accepted range and half within
//!   the daily sweep's span at sub-day granularity.
//!
//! [Howard Hinnant's `civil_from_days`]: http://howardhinnant.github.io/date_algorithms.html

#![cfg(not(miri))]
#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

use etw::Timestamp;
use windows::Win32::{
    Foundation::{FILETIME, SYSTEMTIME},
    System::Time::FileTimeToSystemTime,
};

const TICKS_PER_SEC: i64 = 10_000_000;
const SECS_PER_DAY: i64 = 86_400;
const TICKS_PER_DAY: i64 = SECS_PER_DAY * TICKS_PER_SEC;

/// Days from 1601-01-01 to 2600-12-31 inclusive: 1000 years, of which 242 are leap
/// (250 divisible by 4, less the 10 divisible by 100, plus 2000 and 2400 back).
/// `sweep_endpoints_are_the_years_claimed` checks this arithmetic against the OS.
const DAYS_1601_TO_2601: i64 = 1000 * 365 + 242;

/// Renders `ticks` the way `Display` did before it was reimplemented: the six
/// `SYSTEMTIME` fields from Win32, with the sub-second digits — which
/// `SYSTEMTIME` cannot carry at 100 ns resolution — from the tick count itself.
///
/// `None` when Win32 refuses the conversion.
fn win32_iso8601(ticks: i64) -> Option<String> {
    let filetime = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut systemtime = SYSTEMTIME::default();
    // SAFETY: both pointers address live, correctly typed locals.
    unsafe { FileTimeToSystemTime(&raw const filetime, &raw mut systemtime) }.ok()?;

    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:07}Z",
        systemtime.wYear,
        systemtime.wMonth,
        systemtime.wDay,
        systemtime.wHour,
        systemtime.wMinute,
        systemtime.wSecond,
        ticks % TICKS_PER_SEC,
    ))
}

fn win32_accepts(ticks: i64) -> bool {
    win32_iso8601(ticks).is_some()
}

/// Asserts `Display` renders the six calendar fields Win32 does, and falls back to
/// the raw `i64` on exactly the inputs Win32 rejects.
#[track_caller]
fn assert_agrees(ticks: i64) {
    let expected = win32_iso8601(ticks).unwrap_or_else(|| ticks.to_string());
    assert_eq!(
        Timestamp::new(ticks).to_string(),
        expected,
        "ticks: {ticks}"
    );
}

/// Returns `(last_false, first_true)` for a `predicate` that flips exactly once
/// between `low` and `high`.
fn bisect(mut low: i64, mut high: i64, predicate: impl Fn(i64) -> bool) -> (i64, i64) {
    assert!(!predicate(low), "predicate must be false at low = {low}");
    assert!(predicate(high), "predicate must be true at high = {high}");

    // i128 throughout: `high - low` overflows when low is i64::MIN.
    while i128::from(high) - i128::from(low) > 1 {
        let mid = i128::midpoint(i128::from(low), i128::from(high)) as i64;
        if predicate(mid) {
            high = mid;
        } else {
            low = mid;
        }
    }
    (low, high)
}

/// Derives the range Win32 accepts and pins it, then checks `Display` switches to its
/// raw-`i64` fallback on precisely that boundary.
///
/// The pinned values are what the reimplementation encodes as `self.0 < 0`. If Win32
/// ever moves them, that guard is wrong before any formatting is even attempted, and
/// this is the test that says so.
#[test]
fn display_falls_back_exactly_where_win32_refuses() {
    assert!(win32_accepts(0), "FILETIME 0 (1601-01-01) must convert");

    let (last_rejected, first_accepted) = bisect(i64::MIN, 0, win32_accepts);
    let last_accepted = if win32_accepts(i64::MAX) {
        i64::MAX
    } else {
        bisect(0, i64::MAX, |ticks| !win32_accepts(ticks)).0
    };

    println!("FileTimeToSystemTime accepts [{first_accepted}, {last_accepted}]");

    assert_eq!(
        first_accepted, 0,
        "Win32 now rejects up to {last_rejected}, not up to -1 — Display's \
         `self.0 < 0` fallback guard no longer matches it"
    );
    assert_eq!(
        last_accepted,
        i64::MAX,
        "Win32 has grown an upper limit that Display does not fall back on"
    );

    for ticks in [i64::MIN, last_rejected, first_accepted, last_accepted] {
        assert_agrees(ticks);
    }
}

/// Every day from 1601-01-01 to 2600-12-31, at a time of day that walks the whole
/// day across the sweep so the hour/minute/second fields are exercised too.
#[test]
fn agrees_on_every_day_from_1601_to_2600() {
    for day in 0..DAYS_1601_TO_2601 {
        // 37 s per day: prime, and not a factor of 86 400, so the offset visits every
        // second of the day rather than settling into a short cycle.
        let secs_of_day = day * 37 % SECS_PER_DAY;
        let subsec_ticks = day * 9973 % TICKS_PER_SEC;
        assert_agrees(day * TICKS_PER_DAY + secs_of_day * TICKS_PER_SEC + subsec_ticks);
    }
}

/// Guards `DAYS_1601_TO_2601` against a miscounted leap year, which would silently
/// shorten the sweep above rather than fail it.
#[test]
fn sweep_endpoints_are_the_years_claimed() {
    let first = win32_iso8601(0).unwrap();
    let last = win32_iso8601((DAYS_1601_TO_2601 - 1) * TICKS_PER_DAY).unwrap();
    let past_end = win32_iso8601(DAYS_1601_TO_2601 * TICKS_PER_DAY).unwrap();

    assert!(first.starts_with("1601-01-01"), "got: {first}");
    assert!(last.starts_with("2600-12-31"), "got: {last}");
    assert!(past_end.starts_with("2601-01-01"), "got: {past_end}");
}

/// 100k values from a fixed seed: half across the entire accepted range, where the
/// era arithmetic runs at its largest, and half inside the daily sweep's span, where
/// the sub-day component is what varies.
#[test]
fn agrees_on_pseudorandom_values() {
    let mut state = 0x2545_F491_4F6C_DD1D_u64;

    for _ in 0..50_000 {
        assert_agrees((splitmix64(&mut state) >> 1) as i64);
    }
    for _ in 0..50_000 {
        let span = (DAYS_1601_TO_2601 * TICKS_PER_DAY) as u64;
        assert_agrees((splitmix64(&mut state) % span) as i64);
    }
}

/// splitmix64. Fixed seed, no dev-dependency: a failure has to reproduce.
const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
