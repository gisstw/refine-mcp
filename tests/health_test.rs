use std::fmt::Write;
use std::path::PathBuf;

use refine_mcp::health::compute_health;

#[test]
fn health_for_php_file() {
    let source = r"<?php
class Foo {
    public function simple($x) {
        return $x + 1;
    }

    public function complex($a, $b, $c) {
        if ($a > 0) {
            if ($b > 0) {
                foreach ($c as $item) {
                    if ($item->valid) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
";
    let report = compute_health(source, &PathBuf::from("test.php"), "php");
    assert_eq!(report.functions.len(), 2);

    let simple = report
        .functions
        .iter()
        .find(|f| f.name == "simple")
        .unwrap();
    assert_eq!(simple.param_count, 1);
    assert!(simple.max_nesting_depth <= 1);

    let complex = report
        .functions
        .iter()
        .find(|f| f.name == "complex")
        .unwrap();
    assert_eq!(complex.param_count, 3);
    assert!(
        complex.max_nesting_depth >= 3,
        "expected depth >= 3, got {}",
        complex.max_nesting_depth
    );
    assert!(
        complex.branch_count >= 3,
        "expected branches >= 3, got {}",
        complex.branch_count
    );
}

#[test]
fn health_warns_on_long_function() {
    let mut lines = String::from("<?php\nfunction longFunc() {\n");
    for i in 0..60 {
        let _ = writeln!(lines, "    $x{i} = {i};");
    }
    lines.push_str("}\n");

    let report = compute_health(&lines, &PathBuf::from("test.php"), "php");
    assert_eq!(report.functions.len(), 1);
    assert!(report.functions[0].lines > 50);
    assert!(report.warnings.iter().any(|w| w.contains("longFunc")));
}

#[test]
fn health_for_rust_file() {
    let source = r"
fn simple(x: i32) -> i32 {
    x + 1
}

fn branchy(a: i32, b: Option<i32>) -> i32 {
    if a > 0 {
        match b {
            Some(v) => v,
            None => 0,
        }
    } else {
        -1
    }
}
";
    let report = compute_health(source, &PathBuf::from("test.rs"), "rust");
    assert_eq!(report.functions.len(), 2);

    let branchy = report
        .functions
        .iter()
        .find(|f| f.name == "branchy")
        .unwrap();
    assert!(
        branchy.branch_count >= 2,
        "expected >= 2, got {}",
        branchy.branch_count
    );
}

#[test]
fn health_warns_on_many_params() {
    let source = r"<?php
function tooManyParams($a, $b, $c, $d, $e, $f) {
    return $a;
}
";
    let report = compute_health(source, &PathBuf::from("test.php"), "php");
    assert_eq!(report.functions.len(), 1);
    assert_eq!(report.functions[0].param_count, 6);
    assert!(report.warnings.iter().any(|w| w.contains("parameters")));
}
