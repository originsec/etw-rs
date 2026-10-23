//! GitHub release annotation queries for Windows10EtwEvents.
//!
//! Queries the jdu2600/Windows10EtwEvents repository via `gh api graphql`
//! to determine which Windows release introduced each event version.

#![expect(
    clippy::print_stderr,
    reason = "release query functions report progress and warnings to stderr"
)]

use crate::generate::ReleaseMap;

/// Runs `gh api graphql` and returns the parsed JSON, or `None` on failure.
pub fn gh_graphql(query: &str) -> Option<serde_json::Value> {
    let output = match std::process::Command::new("gh")
        .args(["api", "graphql", "-f", &format!("query={query}")])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Warning: failed to run `gh`: {e} — continuing without release annotations");
            return None;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!(
            "Warning: `gh api graphql` failed: {stderr} — continuing without release annotations"
        );
        return None;
    }

    match serde_json::from_slice(&output.stdout) {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!(
                "Warning: failed to parse gh response: {e} — continuing without release annotations"
            );
            None
        }
    }
}

/// Parses a single TSV file's text and inserts `(class_key, event_id, version) → release`
/// entries into `map`, but only if the key is not already present (first-encounter wins).
pub fn parse_tsv_into_map(text: &str, release: &str, is_mof: bool, map: &mut ReleaseMap) {
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue; // skip header
        }
        let cols: Vec<&str> = line.split('\t').collect();

        let (class_key, event_id, version) = if is_mof {
            // MOF TSV: provider, category(class_guid), event_id, version, ...
            if cols.len() < 4 {
                continue;
            }
            let class_guid = cols[1]
                .trim_start_matches('{')
                .trim_end_matches('}')
                .to_lowercase();
            let Some(eid) = cols[2].parse::<u16>().ok() else {
                continue;
            };
            let Some(ver) = cols[3].parse::<u8>().ok() else {
                continue;
            };
            (class_guid, eid, ver)
        } else {
            // Manifest TSV: provider, event_id, version, ...
            if cols.len() < 3 {
                continue;
            }
            let Some(eid) = cols[1].parse::<u16>().ok() else {
                continue;
            };
            let Some(ver) = cols[2].parse::<u8>().ok() else {
                continue;
            };
            (String::new(), eid, ver)
        };

        // First encounter wins — gives "first introduced" semantics
        map.entry((class_key, event_id, version))
            .or_insert_with(|| release.to_owned());
    }
}

/// Queries the jdu2600/Windows10EtwEvents repo via `gh api graphql` to determine
/// which Windows release introduced each `(event_id, version)` pair.
///
/// Uses a two-query approach that walks commit history for the TSV file:
/// 1. Fetch the list of commits that touched the file
/// 2. Batch-fetch the file content at each historical commit
///
/// Processing commits chronologically (oldest first) and inserting on first
/// encounter gives correct "first introduced" semantics — including versions
/// that were later superseded and removed from the current file.
///
/// Returns `None` on any failure (gh not installed, network error, file not found),
/// printing a warning to stderr.
pub fn query_release_info(provider_name: &str, is_mof: bool) -> Option<ReleaseMap> {
    let tsv_path = if is_mof {
        let underscored = provider_name.replace(' ', "_");
        format!("mof/{underscored}.tsv")
    } else {
        format!("manifest/{provider_name}.tsv")
    };

    // Sanitise path before interpolating into GraphQL query
    if tsv_path.contains('"') || tsv_path.contains('\\') || tsv_path.contains("..") {
        eprintln!("Warning: invalid provider name for TSV lookup: {tsv_path}");
        return None;
    }

    // Query 1: fetch commit history for the TSV file path
    let history_query = format!(
        r#"{{ repository(owner: "jdu2600", name: "Windows10EtwEvents") {{
  ref(qualifiedName: "main") {{ target {{ ... on Commit {{
    history(path: "{tsv_path}", first: 100) {{ nodes {{ oid message }} }}
  }} }} }}
}} }}"#
    );

    let json = gh_graphql(&history_query)?;
    let nodes = json
        .pointer("/data/repository/ref/target/history/nodes")
        .and_then(serde_json::Value::as_array)?;

    if nodes.is_empty() {
        eprintln!(
            "Warning: no commits found for {tsv_path} — continuing without release annotations"
        );
        return None;
    }

    // 100 results means we likely hit the pagination limit and are missing
    // the oldest commits — "first introduced" semantics would be wrong.
    if nodes.len() >= 100 {
        eprintln!(
            "Warning: {tsv_path} has 100+ commits — results may be truncated, \
             release annotations could be inaccurate"
        );
    }

    // Collect (oid, release) pairs and reverse to chronological order
    // (GitHub returns newest-first)
    let mut commits: Vec<(&str, String)> = nodes
        .iter()
        .filter_map(|node| {
            let oid = node.get("oid")?.as_str()?;
            let message = node.get("message")?.as_str()?;
            let release = message.lines().next()?.trim().to_owned();
            (!release.is_empty()).then_some((oid, release))
        })
        .collect();
    commits.reverse();

    if commits.is_empty() {
        eprintln!(
            "Warning: no valid commits for {tsv_path} — continuing without release annotations"
        );
        return None;
    }

    eprintln!(
        "Fetching {tsv_path} at {} historical commits...",
        commits.len()
    );

    // Query 2: batch-fetch file content at each historical commit
    let aliases: String = commits
        .iter()
        .enumerate()
        .filter_map(|(i, (oid, _))| {
            if !(oid.len() == 40 && oid.chars().all(|c| c.is_ascii_hexdigit())) {
                eprintln!("Warning: unexpected OID format from GitHub API: {oid} — skipping");
                return None;
            }
            Some(format!(
                r#"  c{i}: object(expression: "{oid}:{tsv_path}") {{ ... on Blob {{ text }} }}"#
            ))
        })
        .collect::<Vec<_>>()
        .join("\n");

    let content_query = format!(
        r#"{{ repository(owner: "jdu2600", name: "Windows10EtwEvents") {{
{aliases}
}} }}"#
    );

    let json = gh_graphql(&content_query)?;
    let repo = json.pointer("/data/repository")?;

    // Process each commit chronologically — first encounter wins
    let mut map = ReleaseMap::new();
    for (i, (_oid, release)) in commits.iter().enumerate() {
        let alias = format!("c{i}");
        if let Some(text) = repo.get(&alias).and_then(|obj| obj.get("text")?.as_str()) {
            parse_tsv_into_map(text, release, is_mof, &mut map);
        }
    }

    if map.is_empty() {
        eprintln!(
            "Warning: no release data found in {tsv_path} — continuing without release annotations"
        );
        return None;
    }

    eprintln!("Loaded {} release annotations from {tsv_path}", map.len());
    Some(map)
}
