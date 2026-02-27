use std::path::PathBuf;

use refine_mcp::dedup::{dedup_findings, impact_score};
use refine_mcp::types::{Finding, FindingStatus, RedTeamId, Severity};

fn make_finding(
    id: &str,
    file: &str,
    line_range: Option<(u32, u32)>,
    title: &str,
    severity: Severity,
    source: RedTeamId,
) -> Finding {
    Finding {
        id: id.to_string(),
        severity,
        title: title.to_string(),
        sources: vec![source],
        file_path: PathBuf::from(file),
        line_range,
        problem: format!("Problem in {title}"),
        attack_scenario: "攻擊場景".to_string(),
        suggested_fix: None,
        affected_plan_steps: Vec::new(),
        status: FindingStatus::New,
        impact_score: 0,
    }
}

// ─── Dedup Tests ───────────────────────────────────────────────

#[test]
fn dedup_merges_overlapping_line_ranges_same_file() {
    let f1 = make_finding(
        "F1",
        "app/Services/Svc.php",
        Some((150, 160)),
        "issue A",
        Severity::Fatal,
        RedTeamId::RtA,
    );
    let f2 = make_finding(
        "F2",
        "app/Services/Svc.php",
        Some((155, 165)),
        "issue A similar",
        Severity::High,
        RedTeamId::RtB,
    );
    let result = dedup_findings(vec![f1, f2]);
    assert_eq!(result.len(), 1);
    // Sources merged from both findings
    assert_eq!(result[0].sources.len(), 2);
    // Higher severity wins
    assert_eq!(result[0].severity, Severity::Fatal);
}

#[test]
fn dedup_keeps_different_files_separate() {
    let f1 = make_finding(
        "F1",
        "app/A.php",
        Some((10, 20)),
        "issue",
        Severity::Fatal,
        RedTeamId::RtA,
    );
    let f2 = make_finding(
        "F2",
        "app/B.php",
        Some((10, 20)),
        "issue",
        Severity::Fatal,
        RedTeamId::RtB,
    );
    let result = dedup_findings(vec![f1, f2]);
    assert_eq!(result.len(), 2);
}

#[test]
fn dedup_keeps_non_overlapping_ranges_in_same_file() {
    let f1 = make_finding(
        "F1",
        "app/Svc.php",
        Some((10, 20)),
        "issue A",
        Severity::Fatal,
        RedTeamId::RtA,
    );
    let f2 = make_finding(
        "F2",
        "app/Svc.php",
        Some((100, 110)),
        "issue B",
        Severity::Fatal,
        RedTeamId::RtB,
    );
    let result = dedup_findings(vec![f1, f2]);
    assert_eq!(result.len(), 2);
}

#[test]
fn dedup_merges_similar_titles_same_file_no_line_range() {
    let f1 = make_finding(
        "F1",
        "app/Svc.php",
        None,
        "cancelAndRefund race condition",
        Severity::Fatal,
        RedTeamId::RtA,
    );
    let f2 = make_finding(
        "F2",
        "app/Svc.php",
        None,
        "cancelAndRefund race condition vulnerability",
        Severity::High,
        RedTeamId::RtB,
    );
    let result = dedup_findings(vec![f1, f2]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].sources.len(), 2);
}

#[test]
fn dedup_keeps_dissimilar_titles_same_file_no_line_range() {
    let f1 = make_finding(
        "F1",
        "app/Svc.php",
        None,
        "cancel refund race",
        Severity::Fatal,
        RedTeamId::RtA,
    );
    let f2 = make_finding(
        "F2",
        "app/Svc.php",
        None,
        "deposit calculation error",
        Severity::High,
        RedTeamId::RtB,
    );
    let result = dedup_findings(vec![f1, f2]);
    assert_eq!(result.len(), 2);
}

// ─── Impact Scoring Tests ──────────────────────────────────────

#[test]
fn payment_service_scores_higher_than_view() {
    let payment = make_finding(
        "F1",
        "app/Services/PaymentService.php",
        None,
        "lock race",
        Severity::Fatal,
        RedTeamId::RtA,
    );
    let view = make_finding(
        "H1",
        "resources/views/dashboard.blade.php",
        None,
        "display issue",
        Severity::High,
        RedTeamId::RtA,
    );
    assert!(impact_score(&payment) > impact_score(&view));
}

#[test]
fn fatal_scores_higher_than_high_same_domain() {
    let fatal = make_finding(
        "F1",
        "app/Services/ReservationService.php",
        None,
        "TOCTOU race",
        Severity::Fatal,
        RedTeamId::RtA,
    );
    let high = make_finding(
        "H1",
        "app/Services/ReservationService.php",
        None,
        "missing transaction",
        Severity::High,
        RedTeamId::RtA,
    );
    assert!(impact_score(&fatal) > impact_score(&high));
}

#[test]
fn multi_source_scores_higher() {
    let single = make_finding(
        "F1",
        "app/Services/Svc.php",
        None,
        "issue",
        Severity::Fatal,
        RedTeamId::RtA,
    );
    let mut multi = make_finding(
        "F2",
        "app/Services/Svc.php",
        None,
        "issue",
        Severity::Fatal,
        RedTeamId::RtA,
    );
    multi.sources = vec![RedTeamId::RtA, RedTeamId::RtB];
    assert!(impact_score(&multi) > impact_score(&single));
}

// ─── Dedup assigns impact scores ───────────────────────────────

#[test]
fn dedup_assigns_impact_scores() {
    let f1 = make_finding(
        "F1",
        "app/Services/PaymentService.php",
        Some((10, 20)),
        "issue",
        Severity::Fatal,
        RedTeamId::RtA,
    );
    let result = dedup_findings(vec![f1]);
    assert!(result[0].impact_score > 0);
}
