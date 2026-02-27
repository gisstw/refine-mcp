use std::path::PathBuf;

use refine_mcp::facts::php::extract_php_facts;
use refine_mcp::facts::types::*;

#[test]
fn extracts_all_methods() {
    let source = include_str!("fixtures/sample_service.php");
    let path = PathBuf::from("tests/fixtures/sample_service.php");
    let table = extract_php_facts(&path, source).expect("parse should succeed");

    assert_eq!(table.language, Language::Php);
    assert_eq!(table.functions.len(), 3);
    assert_eq!(table.functions[0].name, "cancelAndRefund");
    assert_eq!(table.functions[1].name, "createOnlineReservation");
    assert_eq!(table.functions[2].name, "modifyReservation");
}

#[test]
fn extracts_return_types() {
    let source = include_str!("fixtures/sample_service.php");
    let path = PathBuf::from("tests/fixtures/sample_service.php");
    let table = extract_php_facts(&path, source).expect("parse should succeed");

    assert_eq!(table.functions[0].return_type.as_deref(), Some("bool"));
    assert_eq!(
        table.functions[1].return_type.as_deref(),
        Some("Reservation")
    );
    // modifyReservation has no return type
    assert!(table.functions[2].return_type.is_none());
}

#[test]
fn extracts_parameters() {
    let source = include_str!("fixtures/sample_service.php");
    let path = PathBuf::from("tests/fixtures/sample_service.php");
    let table = extract_php_facts(&path, source).expect("parse should succeed");

    let cancel = &table.functions[0];
    assert_eq!(cancel.parameters.len(), 1);
    assert_eq!(cancel.parameters[0].name, "$reservationId");
    assert_eq!(cancel.parameters[0].type_hint.as_deref(), Some("int"));

    let modify = &table.functions[2];
    assert_eq!(modify.parameters.len(), 2);
    assert_eq!(modify.parameters[0].name, "$id");
    assert_eq!(modify.parameters[1].name, "$changes");
    assert_eq!(modify.parameters[1].type_hint.as_deref(), Some("array"));
}

#[test]
fn detects_transaction() {
    let source = include_str!("fixtures/sample_service.php");
    let path = PathBuf::from("tests/fixtures/sample_service.php");
    let table = extract_php_facts(&path, source).expect("parse should succeed");

    // cancelAndRefund has DB::transaction
    assert!(table.functions[0].transaction.is_some());
    let tx = table.functions[0].transaction.as_ref().unwrap();
    assert!(tx.has_lock_for_update);

    // createOnlineReservation: no transaction
    assert!(table.functions[1].transaction.is_none());

    // modifyReservation: no transaction
    assert!(table.functions[2].transaction.is_none());
}

#[test]
fn detects_locks() {
    let source = include_str!("fixtures/sample_service.php");
    let path = PathBuf::from("tests/fixtures/sample_service.php");
    let table = extract_php_facts(&path, source).expect("parse should succeed");

    // cancelAndRefund has lockForUpdate
    assert!(!table.functions[0].locks.is_empty());
    assert_eq!(table.functions[0].locks[0].kind, LockKind::LockForUpdate);

    // modifyReservation: no lock (potential TOCTOU)
    assert!(table.functions[2].locks.is_empty());
}

#[test]
fn detects_catch_blocks() {
    let source = include_str!("fixtures/sample_service.php");
    let path = PathBuf::from("tests/fixtures/sample_service.php");
    let table = extract_php_facts(&path, source).expect("parse should succeed");

    let cancel = &table.functions[0];
    assert_eq!(cancel.catch_blocks.len(), 1);
    assert!(cancel.catch_blocks[0].catches.contains("Exception"));
    assert_eq!(cancel.catch_blocks[0].action, CatchAction::LogAndReturn);
}

#[test]
fn detects_state_mutations() {
    let source = include_str!("fixtures/sample_service.php");
    let path = PathBuf::from("tests/fixtures/sample_service.php");
    let table = extract_php_facts(&path, source).expect("parse should succeed");

    // createOnlineReservation: 2 creates
    let create = &table.functions[1];
    let creates: Vec<_> = create
        .state_mutations
        .iter()
        .filter(|m| m.kind == MutationKind::Create)
        .collect();
    assert_eq!(creates.len(), 2);

    // modifyReservation: 1 update
    let modify = &table.functions[2];
    assert!(modify
        .state_mutations
        .iter()
        .any(|m| m.kind == MutationKind::Update));
}

#[test]
fn detects_null_risks() {
    let source = include_str!("fixtures/sample_service.php");
    let path = PathBuf::from("tests/fixtures/sample_service.php");
    let table = extract_php_facts(&path, source).expect("parse should succeed");

    // modifyReservation: Reservation::find($id) without null check
    let modify = &table.functions[2];
    assert!(!modify.null_risks.is_empty());
}

#[test]
fn generates_warnings_for_multi_mutation_without_transaction() {
    let source = include_str!("fixtures/sample_service.php");
    let path = PathBuf::from("tests/fixtures/sample_service.php");
    let table = extract_php_facts(&path, source).expect("parse should succeed");

    // createOnlineReservation: 2 creates without transaction → warning
    let has_warning = table
        .warnings
        .iter()
        .any(|w: &String| w.contains("createOnlineReservation") && w.contains("transaction"));
    assert!(has_warning);
}
