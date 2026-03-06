use std::path::Path;
use std::sync::LazyLock;

use anyhow::Context;
use regex::Regex;

use super::types::{ColumnFact, ForeignKeyFact, SchemaSnapshot, SchemaTable};

// ─── Compiled Regexes ──────────────────────────────────────

static RE_SCHEMA_CREATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Schema::create\(\s*['"]([^'"]+)['"]"#).expect("valid regex")
});

static RE_SCHEMA_TABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Schema::table\(\s*['"]([^'"]+)['"]"#).expect("valid regex")
});

static RE_COLUMN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\$table->(id|increments|bigIncrements|tinyIncrements|integer|tinyInteger|smallInteger|mediumInteger|bigInteger|unsignedInteger|unsignedTinyInteger|unsignedSmallInteger|unsignedBigInteger|float|double|decimal|unsignedDecimal|string|char|text|mediumText|longText|boolean|date|dateTime|dateTimeTz|time|timeTz|timestamp|timestampTz|timestamps|timestampsTz|json|jsonb|binary|uuid|enum|foreignId|morphs|nullableMorphs|rememberToken|softDeletes)\(\s*(?:['"]([^'"]*)['"]\s*)?[^)]*\)(.*)"#,
    )
    .expect("valid regex")
});

static RE_NULLABLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"->nullable\(\s*\)").expect("valid regex"));

static RE_DEFAULT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"->default\(\s*([^)]+)\s*\)").expect("valid regex")
});

static RE_FOREIGN_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\$table->foreign\(\s*['"]([^'"]+)['"]\s*\)\s*->references\(\s*['"]([^'"]+)['"]\s*\)\s*->on\(\s*['"]([^'"]+)['"]\s*\)"#,
    )
    .expect("valid regex")
});

static RE_ON_DELETE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"->onDelete\(\s*['"]([^'"]+)['"]\s*\)"#).expect("valid regex")
});

static RE_INDEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$table->(?:index|unique)\(\s*['"]([^'"]+)['"]\s*\)"#).expect("valid regex")
});

// ─── Public API ────────────────────────────────────────────

/// Scans all `.php` files in `migration_dir` and returns a unified schema snapshot.
pub fn extract_migration_facts(migration_dir: &Path) -> anyhow::Result<SchemaSnapshot> {
    let mut files: Vec<_> = std::fs::read_dir(migration_dir)
        .with_context(|| format!("reading migration dir: {}", migration_dir.display()))?
        .filter_map(Result::ok)
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "php")
        })
        .map(|e| e.path())
        .collect();

    files.sort();

    let mut snapshot = SchemaSnapshot::default();

    for file in &files {
        let content = std::fs::read_to_string(file)
            .with_context(|| format!("reading migration file: {}", file.display()))?;
        parse_migration_file(&content, file, &mut snapshot);
    }

    // Generate type warnings for all tables
    let mut warnings = Vec::new();
    for table in &snapshot.tables {
        detect_type_warnings(table, &mut warnings);
    }
    warnings.sort();
    snapshot.type_warnings = warnings;

    // Sort tables by name for deterministic output
    snapshot.tables.sort_by(|a, b| a.table_name.cmp(&b.table_name));

    Ok(snapshot)
}

/// Detect type warnings for a schema table.
pub fn detect_type_warnings(table: &SchemaTable, warnings: &mut Vec<String>) {
    for col in &table.columns {
        // Rule 1: VARCHAR used for monetary column
        if col.col_type == "string" {
            let lower = col.name.to_lowercase();
            if lower.contains("price")
                || lower.contains("amount")
                || lower.contains("total")
                || lower.contains("fee")
                || lower.contains("cost")
            {
                warnings.push(format!(
                    "{}.{}: VARCHAR used for monetary column",
                    table.table_name, col.name
                ));
            }
        }

        // Rule 2: ENUM warning
        if col.col_type == "enum" {
            warnings.push(format!(
                "{}.{}: ENUM values outside defined set silently rejected",
                table.table_name, col.name
            ));
        }
    }
}

// ─── Internal parsing ──────────────────────────────────────

fn parse_migration_file(content: &str, file: &Path, snapshot: &mut SchemaSnapshot) {
    let mut current_table: Option<String> = None;

    for line in content.lines() {
        // Check for Schema::create or Schema::table — both set current table context
        if let Some(table_name) = extract_schema_target(line) {
            current_table = Some(table_name.clone());
            ensure_table_exists(snapshot, table_name, file);
            continue;
        }

        let Some(ref table_name) = current_table else {
            continue;
        };

        if line.trim().starts_with("});") {
            current_table = None;
            continue;
        }

        let table = snapshot
            .tables
            .iter_mut()
            .find(|t| &t.table_name == table_name)
            .expect("table must exist");

        parse_table_line(line, table);
    }
}

/// Returns the table name from `Schema::create(...)` or `Schema::table(...)`.
fn extract_schema_target(line: &str) -> Option<String> {
    RE_SCHEMA_CREATE
        .captures(line)
        .or_else(|| RE_SCHEMA_TABLE.captures(line))
        .map(|cap| cap[1].to_string())
}

/// Ensures a table entry exists in the snapshot; adds one if missing.
fn ensure_table_exists(snapshot: &mut SchemaSnapshot, table_name: String, file: &Path) {
    if !snapshot.tables.iter().any(|t| t.table_name == table_name) {
        snapshot.tables.push(SchemaTable {
            table_name,
            columns: Vec::new(),
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
            source_file: file.to_path_buf(),
        });
    }
}

/// Parses a single line inside a `Schema::create/table` block.
fn parse_table_line(line: &str, table: &mut SchemaTable) {
    // Check for foreign key
    if let Some(cap) = RE_FOREIGN_KEY.captures(line) {
        let fk = ForeignKeyFact {
            column: cap[1].to_string(),
            references_table: cap[3].to_string(),
            references_column: cap[2].to_string(),
            on_delete: RE_ON_DELETE.captures(line).map(|c| c[1].to_string()),
        };
        table.foreign_keys.push(fk);
        return;
    }

    // Check for index
    if let Some(cap) = RE_INDEX.captures(line) {
        table.indexes.push(cap[1].to_string());
        return;
    }

    // Check for column definition
    let Some(cap) = RE_COLUMN.captures(line) else {
        return;
    };

    let col_type = cap[1].to_string();
    let col_name = match cap.get(2) {
        Some(m) if !m.as_str().is_empty() => m.as_str().to_string(),
        _ => {
            // Methods without a column name argument
            match col_type.as_str() {
                "timestamps" | "timestampsTz" => {
                    add_column_if_missing(table, "created_at", "timestamp", false, false, None);
                    add_column_if_missing(table, "updated_at", "timestamp", true, false, None);
                    return;
                }
                "rememberToken" => "remember_token".to_string(),
                "softDeletes" => "deleted_at".to_string(),
                "id" => "id".to_string(),
                // morphs/nullableMorphs without name arg — skip
                _ => return,
            }
        }
    };

    // Handle morphs specially — they create two columns
    if col_type == "morphs" || col_type == "nullableMorphs" {
        let nullable = col_type == "nullableMorphs";
        add_column_if_missing(table, &format!("{col_name}_type"), "string", nullable, false, None);
        add_column_if_missing(table, &format!("{col_name}_id"), "unsignedBigInteger", nullable, false, None);
        return;
    }

    let trailing = cap.get(3).map_or("", |m| m.as_str());

    let nullable =
        RE_NULLABLE.is_match(trailing) || col_type == "softDeletes" || col_type == "nullableMorphs";

    let (has_default, default_value) = if let Some(def_cap) = RE_DEFAULT.captures(trailing) {
        let raw = def_cap[1].trim().to_string();
        let stripped = raw
            .trim_start_matches('\'')
            .trim_start_matches('"')
            .trim_end_matches('\'')
            .trim_end_matches('"')
            .to_string();
        (true, Some(stripped))
    } else {
        (false, None)
    };

    add_column_if_missing(table, &col_name, &col_type, nullable, has_default, default_value);
}

fn add_column_if_missing(
    table: &mut SchemaTable,
    name: &str,
    col_type: &str,
    nullable: bool,
    has_default: bool,
    default_value: Option<String>,
) {
    // Skip if column already exists
    if table.columns.iter().any(|c| c.name == name) {
        return;
    }
    table.columns.push(ColumnFact {
        name: name.to_string(),
        col_type: col_type.to_string(),
        nullable,
        has_default,
        default_value,
    });
}

// ─── Tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_migration(dir: &Path, name: &str, content: &str) {
        fs::write(dir.join(name), content).expect("write migration");
    }

    #[test]
    fn parse_basic_migration() {
        let dir = TempDir::new().unwrap();
        write_migration(
            dir.path(),
            "2024_01_01_000000_create_posts_table.php",
            r#"<?php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('posts', function (Blueprint $table) {
            $table->id();
            $table->string('title');
            $table->text('body')->nullable();
            $table->boolean('published')->default(false);
            $table->timestamps();
        });
    }
};
"#,
        );

        let snapshot = extract_migration_facts(dir.path()).unwrap();
        assert_eq!(snapshot.tables.len(), 1);
        let t = &snapshot.tables[0];
        assert_eq!(t.table_name, "posts");

        // id, title, body, published, created_at, updated_at
        assert_eq!(t.columns.len(), 6);

        let title = t.columns.iter().find(|c| c.name == "title").unwrap();
        assert_eq!(title.col_type, "string");
        assert!(!title.nullable);

        let body = t.columns.iter().find(|c| c.name == "body").unwrap();
        assert_eq!(body.col_type, "text");
        assert!(body.nullable);

        let published = t.columns.iter().find(|c| c.name == "published").unwrap();
        assert_eq!(published.col_type, "boolean");
        assert!(published.has_default);
        assert_eq!(published.default_value.as_deref(), Some("false"));
    }

    #[test]
    fn parse_foreign_key() {
        let dir = TempDir::new().unwrap();
        write_migration(
            dir.path(),
            "2024_01_02_000000_create_comments_table.php",
            r#"<?php
Schema::create('comments', function (Blueprint $table) {
    $table->id();
    $table->unsignedBigInteger('post_id');
    $table->text('body');
    $table->foreign('post_id')->references('id')->on('posts')->onDelete('cascade');
});
"#,
        );

        let snapshot = extract_migration_facts(dir.path()).unwrap();
        let t = &snapshot.tables[0];
        assert_eq!(t.foreign_keys.len(), 1);

        let fk = &t.foreign_keys[0];
        assert_eq!(fk.column, "post_id");
        assert_eq!(fk.references_column, "id");
        assert_eq!(fk.references_table, "posts");
        assert_eq!(fk.on_delete.as_deref(), Some("cascade"));
    }

    #[test]
    fn detect_varchar_price_warning() {
        let table = SchemaTable {
            table_name: "products".to_string(),
            columns: vec![ColumnFact {
                name: "price".to_string(),
                col_type: "string".to_string(),
                nullable: false,
                has_default: false,
                default_value: None,
            }],
            foreign_keys: vec![],
            indexes: vec![],
            source_file: "test.php".into(),
        };

        let mut warnings = Vec::new();
        detect_type_warnings(&table, &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("VARCHAR used for monetary column"));
    }

    #[test]
    fn detect_enum_warning() {
        let table = SchemaTable {
            table_name: "orders".to_string(),
            columns: vec![ColumnFact {
                name: "status".to_string(),
                col_type: "enum".to_string(),
                nullable: false,
                has_default: false,
                default_value: None,
            }],
            foreign_keys: vec![],
            indexes: vec![],
            source_file: "test.php".into(),
        };

        let mut warnings = Vec::new();
        detect_type_warnings(&table, &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("ENUM values outside defined set silently rejected"));
    }

    #[test]
    fn schema_table_alterations_merge() {
        let dir = TempDir::new().unwrap();

        // First migration creates the table
        write_migration(
            dir.path(),
            "2024_01_01_000000_create_users_table.php",
            r#"<?php
Schema::create('users', function (Blueprint $table) {
    $table->id();
    $table->string('name');
    $table->string('email');
});
"#,
        );

        // Second migration alters the table
        write_migration(
            dir.path(),
            "2024_01_02_000000_add_avatar_to_users_table.php",
            r#"<?php
Schema::table('users', function (Blueprint $table) {
    $table->string('avatar')->nullable();
});
"#,
        );

        let snapshot = extract_migration_facts(dir.path()).unwrap();
        // Should have only ONE table entry, with merged columns
        assert_eq!(snapshot.tables.len(), 1);
        let t = &snapshot.tables[0];
        assert_eq!(t.table_name, "users");
        // id, name, email, avatar
        assert_eq!(t.columns.len(), 4);
        assert!(t.columns.iter().any(|c| c.name == "avatar" && c.nullable));
    }
}
