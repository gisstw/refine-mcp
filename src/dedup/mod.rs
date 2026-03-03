use crate::types::{Finding, Severity};

// ─── Dedup Configuration ───────────────────────────────────────

/// Minimum title similarity (normalized Levenshtein) to consider two findings
/// as duplicates when they share the same file but have no overlapping line range.
const TITLE_SIMILARITY_THRESHOLD: f64 = 0.85;

// ─── Public API ────────────────────────────────────────────────

/// Deduplicate findings by file path + line range overlap + title similarity.
///
/// Merge logic:
/// - Same file + overlapping line ranges → merge
/// - Same file + no line ranges + similar titles → merge
/// - On merge: combine sources, keep higher severity, keep longer problem text
/// - After dedup: assign impact scores
#[must_use]
pub fn dedup_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    // Only check recent entries in merged (same file, nearby lines)
    // Look back at most LOOK_BACK items to catch nearby duplicates
    const LOOK_BACK: usize = 10;

    if findings.len() <= 1 {
        for f in &mut findings {
            f.impact_score = impact_score(f);
        }
        return findings;
    }

    // Sort by (file_path, line_start) for locality — enables O(n·k) merge
    // where k is the look-back window (constant) instead of O(n²)
    findings.sort_by(|a, b| {
        a.file_path.cmp(&b.file_path).then_with(|| {
            let a_start = a.line_range.map_or(0, |r| r.0);
            let b_start = b.line_range.map_or(0, |r| r.0);
            a_start.cmp(&b_start)
        })
    });

    let mut merged: Vec<Finding> = Vec::with_capacity(findings.len());

    for finding in findings {
        let mut was_merged = false;

        let start = merged.len().saturating_sub(LOOK_BACK);
        for existing in &mut merged[start..] {
            if should_merge(existing, &finding) {
                merge_into(existing, &finding);
                was_merged = true;
                break;
            }
        }

        if !was_merged {
            merged.push(finding);
        }
    }

    // Assign impact scores after dedup (source count may have changed)
    for f in &mut merged {
        f.impact_score = impact_score(f);
    }

    // Sort by impact score descending
    merged.sort_by(|a, b| b.impact_score.cmp(&a.impact_score));

    merged
}

/// Calculate impact score for a single finding.
///
/// Score = `severity_weight` × `domain_weight` + `source_bonus`
///
/// Higher scores indicate higher priority findings.
#[must_use]
pub fn impact_score(finding: &Finding) -> u32 {
    let severity_weight: u32 = match finding.severity {
        Severity::Fatal => 100,
        Severity::High => 60,
    };

    let domain_weight = domain_weight(&finding.file_path.to_string_lossy());

    // Bonus for findings confirmed by multiple red teams
    let source_bonus: u32 = if finding.sources.len() > 1 { 20 } else { 0 };

    severity_weight * domain_weight / 10 + source_bonus
}

// ─── Internal Logic ────────────────────────────────────────────

fn should_merge(existing: &Finding, candidate: &Finding) -> bool {
    // Must be same file
    if existing.file_path != candidate.file_path {
        return false;
    }

    // Check line range overlap
    if let (Some(a), Some(b)) = (existing.line_range, candidate.line_range) {
        ranges_overlap(a, b)
    } else {
        // No overlapping ranges or missing ranges → fall back to title similarity
        let sim = strsim::normalized_levenshtein(&existing.title, &candidate.title);
        sim >= TITLE_SIMILARITY_THRESHOLD
    }
}

fn ranges_overlap(a: (u32, u32), b: (u32, u32)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

fn merge_into(existing: &mut Finding, other: &Finding) {
    // Merge sources (dedup)
    for src in &other.sources {
        if !existing.sources.contains(src) {
            existing.sources.push(*src);
        }
    }

    // Keep higher severity
    if other.severity < existing.severity {
        existing.severity = other.severity;
    }

    // Keep longer problem description (more detailed)
    if other.problem.len() > existing.problem.len() {
        existing.problem.clone_from(&other.problem);
    }

    // Keep longer attack scenario
    if other.attack_scenario.len() > existing.attack_scenario.len() {
        existing.attack_scenario.clone_from(&other.attack_scenario);
    }

    // Merge suggested fix if existing has none
    if existing.suggested_fix.is_none() && other.suggested_fix.is_some() {
        existing.suggested_fix.clone_from(&other.suggested_fix);
    }

    // Expand line range to cover both
    match (existing.line_range, other.line_range) {
        (Some(a), Some(b)) => {
            existing.line_range = Some((a.0.min(b.0), a.1.max(b.1)));
        }
        (None, Some(b)) => {
            existing.line_range = Some(b);
        }
        _ => {}
    }
}

/// Domain weight based on file path patterns.
///
/// Higher weights for financial and service layer code,
/// lower weights for views and config files.
fn domain_weight(path: &str) -> u32 {
    // Fintech / Payment (highest risk)
    if path.contains("Payment")
        || path.contains("Billing")
        || path.contains("Deposit")
        || path.contains("Invoice")
        || path.contains("Checkout")
        || path.contains("payment")
        || path.contains("billing")
        || path.contains("checkout")
    {
        return 30;
    }

    // Core services (high risk)
    if path.contains("Services/") || path.contains("services/") || path.contains("/service") {
        return 20;
    }

    // Controllers / API routes
    if path.contains("Controller")
        || path.contains("controllers/")
        || path.contains("/routes/")
        || path.contains("/handlers/")
    {
        return 15;
    }

    // Models / Domain
    if path.contains("Models/") || path.contains("models/") || path.contains("/domain/") {
        return 12;
    }

    // Views / Templates / Frontend (lower risk)
    if path.contains("views/")
        || path.contains("templates/")
        || path.contains("resources/")
        || path.contains(".blade.php")
        || path.contains(".html")
    {
        return 5;
    }

    // Config / Migration / Test
    if path.contains("config/")
        || path.contains("migration")
        || path.contains("test")
        || path.contains("Test")
    {
        return 3;
    }

    // Default
    10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_overlap_basic() {
        assert!(ranges_overlap((10, 20), (15, 25)));
        assert!(ranges_overlap((10, 20), (20, 30)));
        assert!(!ranges_overlap((10, 20), (21, 30)));
        assert!(ranges_overlap((15, 25), (10, 20)));
    }

    #[test]
    fn domain_weight_order() {
        assert!(
            domain_weight("app/Services/PaymentService.php")
                > domain_weight("app/Services/ReservationService.php")
        );
        assert!(
            domain_weight("app/Services/ReservationService.php")
                > domain_weight("app/Http/Controllers/FooController.php")
        );
        assert!(
            domain_weight("app/Http/Controllers/FooController.php")
                > domain_weight("resources/views/dashboard.blade.php")
        );
    }
}
