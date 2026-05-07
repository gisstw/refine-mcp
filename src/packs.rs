//! Domain packs — project-specific rule overlays for red team prompts (§4).
//!
//! A domain pack is a markdown file shipped with refine-mcp (built-in) or
//! placed in `<project>/.refine/packs/` (user override). Each `## RT-X`
//! section in the file becomes a list of bullet-point reminders that gets
//! injected into the matching red team's prompt — letting the agent use
//! domain knowledge (Laravel idioms, Beds24 quirks, axum patterns) without
//! pre-loading it into every prompt template.
//!
//! ## Failure handling (Tier 2 §0.5 / RT-A3)
//!
//! `load_packs` distinguishes two failure shapes:
//! - **Pack not found**: warning → red team still runs, just without
//!   that domain context. The agent sees the warning so they know.
//! - **Pack file present but malformed**: hard error. Silent
//!   degradation here would hide a real configuration problem.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::types::RedTeamId;

/// One domain pack, with rules grouped by which red team they apply to.
#[derive(Debug, Clone)]
pub struct DomainPack {
    pub name: String,
    pub source: PackSource,
    pub sections: HashMap<RedTeamId, Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackSource {
    /// Loaded from `<project>/.refine/packs/<name>.md` — user override.
    User,
    /// Loaded from refine-mcp's `templates/packs/<name>.md` — defaults.
    Builtin,
}

/// Outcome of attempting to load a list of named packs.
#[derive(Debug, Default)]
pub struct LoadResult {
    pub packs: Vec<DomainPack>,
    /// Pack names the caller asked for that we couldn't locate. Surfaced
    /// to the user as warnings so the agent knows the red team is missing
    /// expected domain context (RT-A3).
    pub missing: Vec<String>,
}

/// Built-in pack registry. Maps pack name → markdown contents shipped with
/// refine-mcp. Adding a pack here requires only an `include_str!` line.
fn builtin_pack(name: &str) -> Option<&'static str> {
    match name {
        "laravel" => Some(include_str!("../templates/packs/laravel.md")),
        "beds24" => Some(include_str!("../templates/packs/beds24.md")),
        "axum-pms" => Some(include_str!("../templates/packs/axum-pms.md")),
        _ => None,
    }
}

/// Load a list of packs by name. Resolution order per name:
/// 1. `<project_root>/.refine/packs/<name>.md` (user override)
/// 2. Built-in pack shipped with refine-mcp
/// 3. Record as missing — caller surfaces a warning
///
/// Malformed pack contents (markdown that doesn't parse to at least one
/// valid `## RT-X` section) return `Err` so the caller can fail-fast
/// rather than silently produce unhelpful prompts.
pub fn load_packs(project_root: &Path, requested: &[String]) -> Result<LoadResult> {
    let mut result = LoadResult::default();
    for name in requested {
        let user_path = project_root.join(".refine/packs").join(format!("{name}.md"));
        if user_path.exists() {
            let content = std::fs::read_to_string(&user_path).with_context(|| {
                format!("reading user pack {}", user_path.display())
            })?;
            let pack = parse_pack(name, &content, PackSource::User).with_context(|| {
                format!("parsing user pack {}", user_path.display())
            })?;
            result.packs.push(pack);
            continue;
        }
        if let Some(builtin) = builtin_pack(name) {
            let pack = parse_pack(name, builtin, PackSource::Builtin)
                .with_context(|| format!("parsing builtin pack '{name}'"))?;
            result.packs.push(pack);
            continue;
        }
        result.missing.push(name.clone());
    }
    Ok(result)
}

/// Render the domain context section that gets injected into a red team
/// prompt for `target`. Returns an empty string when no loaded pack has
/// rules for that team, so the placeholder substitution is a clean no-op.
#[must_use]
pub fn render_for_team(packs: &[DomainPack], target: RedTeamId) -> String {
    use std::fmt::Write;
    let mut sections = Vec::new();
    for pack in packs {
        if let Some(rules) = pack.sections.get(&target) {
            if rules.is_empty() {
                continue;
            }
            let mut block = format!("\n### {} (domain pack: {})\n", pack.name, source_label(pack.source));
            for r in rules {
                let _ = writeln!(block, "- {r}");
            }
            sections.push(block);
        }
    }
    if sections.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "\n## Domain context\n\nDomain-specific rules to weight more heavily for this review:\n",
    );
    for s in sections {
        out.push_str(&s);
    }
    out
}

fn source_label(s: PackSource) -> &'static str {
    match s {
        PackSource::User => "user",
        PackSource::Builtin => "builtin",
    }
}

/// Parse a pack markdown file into structured rules. Recognized section
/// headings: `## RT-A`, `## RT-B`, `## RT-C`, `## RT-D`. Any other heading
/// is ignored (free-form intro text is fine). Bullet items (`- ...`) under
/// each recognized heading become the rules for that red team.
fn parse_pack(name: &str, content: &str, source: PackSource) -> Result<DomainPack> {
    let mut sections: HashMap<RedTeamId, Vec<String>> = HashMap::new();
    let mut current: Option<RedTeamId> = None;
    for raw_line in content.lines() {
        let line = raw_line.trim_end();
        if let Some(rest) = line.strip_prefix("## ") {
            current = match rest.trim().to_uppercase().as_str() {
                s if s.starts_with("RT-A") => Some(RedTeamId::RtA),
                s if s.starts_with("RT-B") => Some(RedTeamId::RtB),
                s if s.starts_with("RT-C") => Some(RedTeamId::RtC),
                s if s.starts_with("RT-D") => Some(RedTeamId::RtD),
                _ => None,
            };
            continue;
        }
        let Some(team) = current else { continue };
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("- ").or_else(|| trimmed.strip_prefix("* ")) {
            let rule = rest.trim().to_string();
            if !rule.is_empty() {
                sections.entry(team).or_default().push(rule);
            }
        }
    }
    if sections.is_empty() {
        return Err(anyhow::anyhow!(
            "pack '{name}' contains no recognized `## RT-A/B/C/D` sections with bullet rules"
        ));
    }
    Ok(DomainPack {
        name: name.to_string(),
        source,
        sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_pack_extracts_rt_sections() {
        let md = "\
# Laravel pack

Some intro text.

## RT-A: Silent Failure
- Mass assignment without $fillable
- find() vs findOrFail()

## RT-C: Schema Drift
- Migration without down()
";
        let pack = parse_pack("laravel", md, PackSource::Builtin).unwrap();
        assert_eq!(pack.sections[&RedTeamId::RtA].len(), 2);
        assert_eq!(pack.sections[&RedTeamId::RtC].len(), 1);
        assert!(!pack.sections.contains_key(&RedTeamId::RtB));
    }

    #[test]
    fn parse_pack_rejects_when_no_sections_found() {
        let md = "# Some pack\n\nJust prose, no rules.\n";
        let err = parse_pack("empty", md, PackSource::Builtin).unwrap_err();
        assert!(
            err.to_string().contains("no recognized"),
            "expected schema error, got: {err}"
        );
    }

    #[test]
    fn load_packs_falls_back_to_builtin_when_user_missing() {
        let tmp = tempdir();
        let result = load_packs(&tmp, &["laravel".to_string()]).unwrap();
        assert_eq!(result.packs.len(), 1);
        assert_eq!(result.packs[0].source, PackSource::Builtin);
        assert!(result.missing.is_empty());
    }

    #[test]
    fn load_packs_prefers_user_over_builtin() {
        let tmp = tempdir();
        let pack_dir = tmp.join(".refine/packs");
        std::fs::create_dir_all(&pack_dir).unwrap();
        let mut f = std::fs::File::create(pack_dir.join("laravel.md")).unwrap();
        writeln!(f, "## RT-A\n- user-supplied rule\n").unwrap();
        let result = load_packs(&tmp, &["laravel".to_string()]).unwrap();
        assert_eq!(result.packs[0].source, PackSource::User);
        assert!(result.packs[0].sections[&RedTeamId::RtA]
            .iter()
            .any(|r| r.contains("user-supplied")));
    }

    #[test]
    fn load_packs_collects_missing_names() {
        let tmp = tempdir();
        let result = load_packs(
            &tmp,
            &["laravel".to_string(), "nonexistent".to_string()],
        )
        .unwrap();
        assert_eq!(result.packs.len(), 1);
        assert_eq!(result.missing, vec!["nonexistent"]);
    }

    #[test]
    fn render_for_team_skips_packs_without_matching_section() {
        let pack = parse_pack(
            "x",
            "## RT-A\n- only RT-A rule\n",
            PackSource::Builtin,
        )
        .unwrap();
        let rendered = render_for_team(&[pack], RedTeamId::RtB);
        assert!(rendered.is_empty(), "RT-B has no rules, expected empty");
    }

    #[test]
    fn render_for_team_includes_pack_name_and_source() {
        let pack = parse_pack(
            "laravel",
            "## RT-A\n- mass assignment\n",
            PackSource::User,
        )
        .unwrap();
        let rendered = render_for_team(&[pack], RedTeamId::RtA);
        assert!(rendered.contains("laravel"));
        assert!(rendered.contains("user"));
        assert!(rendered.contains("mass assignment"));
    }

    fn tempdir() -> std::path::PathBuf {
        // Each call returns a unique, fresh dir so parallel tests don't
        // race over the same path.
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let mut p = std::env::temp_dir();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        p.push(format!(
            "refine-pack-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
