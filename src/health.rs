use std::path::Path;

use tree_sitter::Parser;

use crate::types::{FunctionHealth, HealthReport};

/// Compute health metrics for all functions in a source file.
#[must_use]
pub fn compute_health(source: &str, file: &Path, lang: &str) -> HealthReport {
    let mut parser = Parser::new();
    let language: tree_sitter::Language = match lang {
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "typescript" | "tsx" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        _ => return HealthReport::default(),
    };

    if parser.set_language(&language).is_err() {
        return HealthReport::default();
    }

    let Some(tree) = parser.parse(source, None) else {
        return HealthReport::default();
    };

    let mut report = HealthReport::default();
    collect_functions(&tree.root_node(), source.as_bytes(), file, &mut report);

    // Generate warnings
    for func in &report.functions {
        if func.lines > 50 {
            report.warnings.push(format!(
                "{}: {} is {} lines (consider splitting)",
                file.display(),
                func.name,
                func.lines
            ));
        }
        if func.param_count > 5 {
            report.warnings.push(format!(
                "{}: {} has {} parameters (consider a params struct)",
                file.display(),
                func.name,
                func.param_count
            ));
        }
        if func.max_nesting_depth > 4 {
            report.warnings.push(format!(
                "{}: {} has nesting depth {} (consider early returns)",
                file.display(),
                func.name,
                func.max_nesting_depth
            ));
        }
    }

    report
}

/// Walk the AST to find function/method declarations.
fn collect_functions(
    node: &tree_sitter::Node,
    source: &[u8],
    file: &Path,
    report: &mut HealthReport,
) {
    let kind = node.kind();

    let is_function = matches!(
        kind,
        "function_definition" | "method_declaration" | "function_item" | "function_declaration"
    );

    if is_function {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.utf8_text(source).unwrap_or_default();
            if !name.is_empty() {
                #[allow(clippy::cast_possible_truncation)]
                let start_row = node.start_position().row as u32 + 1;
                #[allow(clippy::cast_possible_truncation)]
                let end_row = node.end_position().row as u32 + 1;
                let lines = end_row.saturating_sub(start_row) + 1;

                let param_count = node
                    .child_by_field_name("parameters")
                    .or_else(|| node.child_by_field_name("formal_parameters"))
                    .map_or(0, |params| count_param_children(&params));

                let (max_depth, branch_count) = node
                    .child_by_field_name("body")
                    .map_or((0, 0), |body| compute_complexity(&body));

                report.functions.push(FunctionHealth {
                    name: name.to_string(),
                    file: file.to_path_buf(),
                    line_range: (start_row, end_row),
                    lines,
                    param_count,
                    max_nesting_depth: max_depth,
                    branch_count,
                });
            }
        }
        // Don't recurse into function bodies for nested functions
        return;
    }

    // Recurse into children
    let child_count = node.child_count();
    for i in 0..child_count {
        if let Some(child) = node.child(i) {
            collect_functions(&child, source, file, report);
        }
    }
}

/// Count parameter children in a parameters node.
fn count_param_children(node: &tree_sitter::Node) -> usize {
    let param_kinds = [
        "simple_parameter",
        "parameter",
        "formal_parameter",
        "typed_parameter",
        "default_parameter",
        "required_parameter",
        "optional_parameter",
        "variadic_parameter",
        "property_promotion_parameter",
    ];

    let mut count = 0;
    let child_count = node.child_count();
    for i in 0..child_count {
        if let Some(child) = node.child(i) {
            if param_kinds.contains(&child.kind()) {
                count += 1;
            }
        }
    }
    count
}

/// Compute max nesting depth and branch count for a subtree.
fn compute_complexity(node: &tree_sitter::Node) -> (u32, u32) {
    let mut max_depth: u32 = 0;
    let mut branch_count: u32 = 0;
    walk_complexity(node, 0, &mut max_depth, &mut branch_count);
    (max_depth, branch_count)
}

fn walk_complexity(
    node: &tree_sitter::Node,
    current_depth: u32,
    max_depth: &mut u32,
    branch_count: &mut u32,
) {
    let kind = node.kind();

    let is_branch = matches!(
        kind,
        "if_statement"
            | "elseif_clause"
            | "for_statement"
            | "foreach_statement"
            | "while_statement"
            | "do_statement"
            | "switch_statement"
            | "match_expression"
            | "try_statement"
            | "for_expression"
            | "while_expression"
            | "loop_expression"
            | "if_expression"
            | "for_in_statement"
            | "for_of_statement"
    );

    let depth = if is_branch {
        *branch_count += 1;
        current_depth + 1
    } else {
        current_depth
    };

    if depth > *max_depth {
        *max_depth = depth;
    }

    let child_count = node.child_count();
    for i in 0..child_count {
        if let Some(child) = node.child(i) {
            walk_complexity(&child, depth, max_depth, branch_count);
        }
    }
}
