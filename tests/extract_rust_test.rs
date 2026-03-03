use std::path::PathBuf;

use refine_mcp::facts::rust_lang::extract_rust_facts;
use refine_mcp::facts::types::*;

#[test]
fn extracts_all_functions() {
    let source = include_str!("fixtures/sample_service.rs");
    let path = PathBuf::from("tests/fixtures/sample_service.rs");
    let table = extract_rust_facts(&path, source).expect("parse should succeed");

    assert_eq!(table.language, Language::Rust);
    assert_eq!(table.functions.len(), 5);
    assert_eq!(table.functions[0].name, "cancel_reservation");
    assert_eq!(table.functions[1].name, "create_reservation");
    assert_eq!(table.functions[2].name, "calculate_total");
    assert_eq!(table.functions[3].name, "risky_update");
    assert_eq!(table.functions[4].name, "with_error_handling");
}

#[test]
fn detects_transaction_with_lock() {
    let source = include_str!("fixtures/sample_service.rs");
    let path = PathBuf::from("tests/fixtures/sample_service.rs");
    let table = extract_rust_facts(&path, source).expect("parse should succeed");

    // cancel_reservation has pool.begin() + FOR UPDATE
    let cancel = &table.functions[0];
    assert!(cancel.transaction.is_some());
    let tx = cancel.transaction.as_ref().unwrap();
    assert!(tx.has_lock_for_update);

    // create_reservation: no transaction
    assert!(table.functions[1].transaction.is_none());

    // calculate_total: pure function, no transaction
    assert!(table.functions[2].transaction.is_none());
}

#[test]
fn detects_sql_mutations() {
    let source = include_str!("fixtures/sample_service.rs");
    let path = PathBuf::from("tests/fixtures/sample_service.rs");
    let table = extract_rust_facts(&path, source).expect("parse should succeed");

    // cancel_reservation: UPDATE
    let cancel = &table.functions[0];
    assert!(
        cancel
            .state_mutations
            .iter()
            .any(|m| m.kind == MutationKind::Update)
    );

    // create_reservation: INSERT
    let create = &table.functions[1];
    assert!(
        create
            .state_mutations
            .iter()
            .any(|m| m.kind == MutationKind::Create)
    );
}

#[test]
fn detects_read_modify_write_without_lock() {
    let source = include_str!("fixtures/sample_service.rs");
    let path = PathBuf::from("tests/fixtures/sample_service.rs");
    let table = extract_rust_facts(&path, source).expect("parse should succeed");

    // risky_update: SELECT + UPDATE without tx/lock → should warn
    let has_warning = table
        .warnings
        .iter()
        .any(|w: &String| w.contains("risky_update") && w.contains("TOCTOU"));
    assert!(has_warning);
}

#[test]
fn detects_unwrap_risk() {
    let source = include_str!("fixtures/sample_service.rs");
    let path = PathBuf::from("tests/fixtures/sample_service.rs");
    let table = extract_rust_facts(&path, source).expect("parse should succeed");

    // with_error_handling has .unwrap()
    let handler = &table.functions[4];
    assert!(!handler.null_risks.is_empty());
    assert!(handler.null_risks[0].expression.contains("unwrap"));
}

#[test]
fn detects_error_swallowing() {
    let source = include_str!("fixtures/sample_service.rs");
    let path = PathBuf::from("tests/fixtures/sample_service.rs");
    let table = extract_rust_facts(&path, source).expect("parse should succeed");

    // with_error_handling: match Err => log + return Ok(()) — swallows error
    let handler = &table.functions[4];
    assert!(!handler.catch_blocks.is_empty());
}

#[test]
fn extracts_return_types() {
    let source = include_str!("fixtures/sample_service.rs");
    let path = PathBuf::from("tests/fixtures/sample_service.rs");
    let table = extract_rust_facts(&path, source).expect("parse should succeed");

    // cancel_reservation -> Result<()>
    assert!(
        table.functions[0]
            .return_type
            .as_deref()
            .unwrap()
            .contains("Result")
    );

    // calculate_total -> Decimal
    assert_eq!(table.functions[2].return_type.as_deref(), Some("Decimal"));
}
