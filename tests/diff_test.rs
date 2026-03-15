use std::path::PathBuf;

use refine_mcp::diff::compute_structural_diff;
use refine_mcp::facts::types::{FunctionFact, ParamFact};

fn make_func(name: &str, params: Vec<(&str, Option<&str>)>, ret: Option<&str>) -> FunctionFact {
    FunctionFact {
        name: name.to_string(),
        line_range: (1, 10),
        return_type: ret.map(String::from),
        parameters: params
            .into_iter()
            .map(|(n, t)| ParamFact {
                name: n.to_string(),
                type_hint: t.map(String::from),
                nullable: false,
            })
            .collect(),
        transaction: None,
        locks: vec![],
        catch_blocks: vec![],
        external_calls: vec![],
        state_mutations: vec![],
        null_risks: vec![],
    }
}

#[test]
fn detects_added_function() {
    let before = vec![];
    let after = vec![make_func("newFunc", vec![], None)];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].name, "newFunc");
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
}

#[test]
fn detects_removed_function() {
    let before = vec![make_func("oldFunc", vec![], None)];
    let after = vec![];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert!(diff.added.is_empty());
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0].name, "oldFunc");
}

#[test]
fn detects_signature_change_return_type() {
    let before = vec![make_func("process", vec![], Some("bool"))];
    let after = vec![make_func("process", vec![], Some("PaymentResult"))];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert_eq!(diff.changed.len(), 1);
    assert!(diff.changed[0].breaking);
    assert!(
        diff.changed[0]
            .reasons
            .iter()
            .any(|r| r.contains("return type"))
    );
}

#[test]
fn detects_signature_change_param_added() {
    let before = vec![make_func("save", vec![("$id", Some("int"))], None)];
    let after = vec![make_func(
        "save",
        vec![("$id", Some("int")), ("$force", Some("bool"))],
        None,
    )];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert_eq!(diff.changed.len(), 1);
    assert!(diff.changed[0].breaking);
}

#[test]
fn unchanged_function_not_reported() {
    let func = make_func("helper", vec![("$x", Some("int"))], Some("string"));
    let before = vec![func.clone()];
    let after = vec![func];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
    assert_eq!(diff.unchanged_count, 1);
}

#[test]
fn detects_param_type_change() {
    let before = vec![make_func("update", vec![("$amount", Some("float"))], None)];
    let after = vec![make_func(
        "update",
        vec![("$amount", Some("Decimal"))],
        None,
    )];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert_eq!(diff.changed.len(), 1);
    assert!(diff.changed[0].breaking);
    assert!(
        diff.changed[0]
            .reasons
            .iter()
            .any(|r| r.contains("type changed"))
    );
}

#[test]
fn detects_param_removed() {
    let before = vec![make_func("render", vec![("$a", None), ("$b", None)], None)];
    let after = vec![make_func("render", vec![("$a", None)], None)];
    let diff = compute_structural_diff(&PathBuf::from("test.php"), &before, &after);
    assert_eq!(diff.changed.len(), 1);
    assert!(diff.changed[0].breaking);
    assert!(
        diff.changed[0]
            .reasons
            .iter()
            .any(|r| r.contains("removed"))
    );
}
