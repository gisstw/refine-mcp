use refine_mcp::parser::parse_red_team_output;
use refine_mcp::types::{RedTeamId, Severity};

#[test]
fn parses_all_findings() {
    let md = include_str!("fixtures/sample_rt_output.md");
    let findings = parse_red_team_output(md).expect("parse should succeed");

    // 2 FATAL + 1 HIGH from RT-A, 1 FATAL + 1 HIGH from RT-B = 5 total
    assert_eq!(findings.len(), 5);
}

#[test]
fn parses_severity_correctly() {
    let md = include_str!("fixtures/sample_rt_output.md");
    let findings = parse_red_team_output(md).expect("parse should succeed");

    let fatals: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Fatal).collect();
    let highs: Vec<_> = findings.iter().filter(|f| f.severity == Severity::High).collect();
    assert_eq!(fatals.len(), 3);
    assert_eq!(highs.len(), 2);
}

#[test]
fn parses_red_team_source() {
    let md = include_str!("fixtures/sample_rt_output.md");
    let findings = parse_red_team_output(md).expect("parse should succeed");

    // First 3 findings from RT-A
    for f in &findings[..3] {
        assert_eq!(f.sources, vec![RedTeamId::RtA]);
    }
    // Last 2 from RT-B
    for f in &findings[3..] {
        assert_eq!(f.sources, vec![RedTeamId::RtB]);
    }
}

#[test]
fn parses_title() {
    let md = include_str!("fixtures/sample_rt_output.md");
    let findings = parse_red_team_output(md).expect("parse should succeed");

    assert!(findings[0].title.contains("cancelAndRefund"));
    assert!(findings[2].title.contains("createOnlineReservation"));
    assert!(findings[3].title.contains("modifyReservation"));
}

#[test]
fn parses_file_path_and_line_range() {
    let md = include_str!("fixtures/sample_rt_output.md");
    let findings = parse_red_team_output(md).expect("parse should succeed");

    assert_eq!(
        findings[0].file_path.to_str().unwrap(),
        "app/Services/ReservationService.php"
    );
    assert_eq!(findings[0].line_range, Some((150, 165)));

    // Single line reference
    assert_eq!(
        findings[1].file_path.to_str().unwrap(),
        "app/Services/DepositService.php"
    );
    assert_eq!(findings[1].line_range, Some((89, 89)));
}

#[test]
fn parses_problem_and_attack_scenario() {
    let md = include_str!("fixtures/sample_rt_output.md");
    let findings = parse_red_team_output(md).expect("parse should succeed");

    assert!(findings[0].problem.contains("refundPayment"));
    assert!(findings[0].attack_scenario.contains("雙重退款"));
}

#[test]
fn parses_suggested_fix() {
    let md = include_str!("fixtures/sample_rt_output.md");
    let findings = parse_red_team_output(md).expect("parse should succeed");

    // First finding has a fix suggestion
    assert!(findings[0].suggested_fix.is_some());
    assert!(findings[0]
        .suggested_fix
        .as_ref()
        .unwrap()
        .contains("saga"));

    // Third finding (HIGH) has no fix
    assert!(findings[2].suggested_fix.is_none());
}
