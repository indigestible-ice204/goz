//! es.exe-compatible argv parsing: `parse_argv(args) -> Result<EsPlan, EsFatal>`.
//!
//! Rules implemented from the voidtools es source:
//!
//! - A token starting with `-` or `/` is a switch candidate. Name matching is
//!   case-sensitive and every dash inside the canonical name is
//!   optional in the input (`-sort-path` == `-sortpath`, `-max-results` ==
//!   `-maxresults`). An input dash is accepted only where the canonical name
//!   has one, so `-d-m` does not match `-dm`.
//! - An unknown `-` switch is fatal (exit 6). An unknown `/` token falls
//!   through to the search text verbatim (es source comment: "allow
//!   /downloads to search for \downloads").
//! - A token consisting solely of dashes (`-`, `--`, `---`, ...) is search
//!   text, never a switch (es `es_is_literal_switch`).
//! - Other `--`-prefixed tokens are goz's native namespace: exactly `--json`,
//!   `--status`, and `--insecure-no-server-check` (case-sensitive, dashes
//!   required). Anything else is fatal (exit 6).
//! - A parameter-taking switch consumes the next token; a missing or
//!   unparseable parameter is fatal (exit 4).
//! - Non-switch tokens become the query: joined with single spaces, in
//!   command-line order, each token preserved as received. Flags may
//!   interleave with query tokens freely.
//!
//! Conservative choices where the research is silent (documented, not
//! observed from es): the `-sort` parameter is matched with the same
//! case-sensitive dash-optional rule as the combined `-sort-*` switches (es
//! uses the same name table for both); an unknown `-sort` value and a
//! non-`u32` `-n` value both map to exit 4 ("bad switch parameter" in modern
//! es terms); when several sort switches appear, the last one wins.

use crate::types::{EsColumn, SortDir, SortKey, SortSpec};

/// es exit code 4: a switch expected an additional parameter that was
/// missing or unparseable.
const EXIT_EXPECTED_PARAM: u8 = 4;
/// es exit code 6: unknown switch.
const EXIT_UNKNOWN_SWITCH: u8 = 6;

/// The fully-resolved plan for one es-compatible invocation.
///
/// Produced by [`parse_argv`]; consumed by the CLI, which resolves
/// process-level concerns (absolutizing `scope`, creating the export file,
/// talking to the daemon).
#[derive(Clone, Debug, PartialEq)]
pub struct EsPlan {
    /// Search text: every non-switch token, joined with single spaces in
    /// command-line order, each token preserved as received.
    pub query: String,
    /// `-path` value, verbatim. The CLI absolutizes it (GetFullPathName
    /// semantics, no existence check); the core stays path-API-free.
    pub scope: Option<String>,
    /// `-n` / `-max-results` value: return only the top N results after
    /// sorting. `None` means unlimited.
    pub limit: Option<u32>,
    /// Optional CSV columns from `-size` / `-dm` / `-date-modified`, in flag
    /// order with es dedupe semantics (a repeated flag moves its column to
    /// the end). `Filename` is always emitted last and is not listed here.
    pub columns: Vec<EsColumn>,
    /// Result order. Defaults to name-ascending (es with no `-sort` flag);
    /// unsuffixed sort switches use es's per-key default direction.
    pub sort: SortSpec,
    /// `-export-csv` value, verbatim. `None` means write results to stdout.
    pub export_csv: Option<String>,
    /// Whether the CSV starts with a UTF-8 BOM. Default true: a
    /// documented goz deviation from stock es (which defaults BOM off).
    /// `-no-utf8-bom` clears it; `-utf8-bom` is accepted and sets it.
    pub bom: bool,
    /// Whether the CSV includes the header row. `-no-header` clears it.
    pub header: bool,
    /// Whether string columns are always double-quoted (es default).
    /// `-no-double-quote` downgrades to quote-only-when-needed.
    pub double_quote: bool,
    /// Case-sensitive matching, from `-case` / `-match-case`. Default off.
    pub match_case: bool,
    /// Native `--json`: emit results as JSON instead of CSV/plain text.
    pub json: bool,
    /// Native `--status`: report daemon/index status instead of searching.
    pub status: bool,
    /// Native `--insecure-no-server-check`: skip the pipe-server owner-SID
    /// verification (dev escape hatch).
    pub insecure_no_server_check: bool,
}

impl Default for EsPlan {
    /// The plan for an empty command line: name-ascending sort and es's
    /// default output shape (header on, always-quote on, BOM on per goz's
    /// deviation).
    fn default() -> Self {
        Self {
            query: String::new(),
            scope: None,
            limit: None,
            columns: Vec::new(),
            sort: SortSpec::default(),
            export_csv: None,
            bom: true,
            header: true,
            double_quote: true,
            match_case: false,
            json: false,
            status: false,
            insecure_no_server_check: false,
        }
    }
}

/// A fatal argv-parse error carrying the es-compatible process exit code.
///
/// Exit-code mapping (from es.exe):
///
/// | Code | es meaning |
/// |------|------------|
/// | 4    | expected an additional parameter after a switch (modern es also uses it for a bad switch parameter) |
/// | 6    | unknown switch |
///
/// The message names the offending token so the CLI can report it on stderr
/// and exit with `exit_code`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct EsFatal {
    /// The process exit code the CLI must terminate with (4 or 6 here).
    pub exit_code: u8,
    /// Human-readable description, including the offending token.
    pub message: String,
}

impl EsFatal {
    /// Exit 6: the token looked like a switch but matched nothing.
    fn unknown_switch(token: &str) -> Self {
        Self {
            exit_code: EXIT_UNKNOWN_SWITCH,
            message: format!("unknown switch: {token}"),
        }
    }

    /// Exit 4: the switch requires a parameter and none followed.
    fn missing_param(token: &str) -> Self {
        Self {
            exit_code: EXIT_EXPECTED_PARAM,
            message: format!("expected an additional parameter after {token}"),
        }
    }

    /// Exit 4: the switch got a parameter it cannot interpret.
    fn bad_param(token: &str, value: &str, expected: &str) -> Self {
        Self {
            exit_code: EXIT_EXPECTED_PARAM,
            message: format!("expected {expected} after {token}, got: {value}"),
        }
    }
}

/// What a matched switch does to the plan.
#[derive(Clone, Copy, Debug)]
enum SwitchAction {
    /// `-n` / `-max-results`: consume the next token as a `u32` limit.
    Limit,
    /// `-path`: consume the next token as the scope, verbatim.
    Scope,
    /// `-export-csv`: consume the next token as the output path, verbatim.
    ExportCsv,
    /// `-sort`: consume the next token as a sort-key name with an optional
    /// `-ascending` / `-descending` suffix.
    SortParam,
    /// `-size` / `-dm` / `-date-modified`: append a column (es dedupe).
    Column(EsColumn),
    /// A combined `-sort-<key>[-ascending|-descending]` switch.
    SortFixed(SortSpec),
    /// `-utf8-bom`: set BOM on (a no-op against goz's default).
    Utf8Bom,
    /// `-no-utf8-bom`: set BOM off.
    NoUtf8Bom,
    /// `-no-header`: suppress the CSV header row.
    NoHeader,
    /// `-no-double-quote`: quote string columns only when needed.
    NoDoubleQuote,
    /// `-case` / `-match-case`: case-sensitive matching.
    MatchCase,
}

/// Every parameterless and parameter-taking switch except the combined
/// `-sort-*` family (generated in [`match_switch`]). Canonical spellings;
/// interior dashes are optional in the input.
const SIMPLE_SWITCHES: &[(&str, SwitchAction)] = &[
    ("n", SwitchAction::Limit),
    ("max-results", SwitchAction::Limit),
    ("path", SwitchAction::Scope),
    ("size", SwitchAction::Column(EsColumn::Size)),
    ("dm", SwitchAction::Column(EsColumn::DateModified)),
    (
        "date-modified",
        SwitchAction::Column(EsColumn::DateModified),
    ),
    ("sort", SwitchAction::SortParam),
    ("export-csv", SwitchAction::ExportCsv),
    ("utf8-bom", SwitchAction::Utf8Bom),
    ("no-utf8-bom", SwitchAction::NoUtf8Bom),
    ("no-header", SwitchAction::NoHeader),
    ("no-double-quote", SwitchAction::NoDoubleQuote),
    ("case", SwitchAction::MatchCase),
    ("match-case", SwitchAction::MatchCase),
];

/// Sort-key spellings accepted by both `-sort <key>` and the combined
/// `-sort-<key>` switches.
const SORT_KEYS: &[(&str, SortKey)] = &[
    ("name", SortKey::Name),
    ("path", SortKey::Path),
    ("size", SortKey::Size),
    ("dm", SortKey::DateModified),
    ("date-modified", SortKey::DateModified),
];

/// Parses an argv slice (excluding `argv[0]`) into an [`EsPlan`].
///
/// Pure and total: no I/O, no environment access, no panics on any input.
/// Fatal parse errors return [`EsFatal`] with the es exit code (4 or 6).
///
/// ```
/// use goz_core::escompat::parse_argv;
///
/// let args: Vec<String> = ["report", "-sortpath", "-n", "10"]
///     .iter()
///     .map(ToString::to_string)
///     .collect();
/// let plan = parse_argv(&args).unwrap();
/// assert_eq!(plan.query, "report");
/// assert_eq!(plan.limit, Some(10));
/// ```
pub fn parse_argv(args: &[String]) -> Result<EsPlan, EsFatal> {
    let mut plan = EsPlan::default();
    let mut query: Vec<&str> = Vec::new();
    let mut rest = args.iter();

    while let Some(token) = rest.next() {
        let token = token.as_str();

        // es literal-switch rule: all-dash tokens are search text.
        if !token.is_empty() && token.bytes().all(|b| b == b'-') {
            query.push(token);
            continue;
        }

        // Native namespace: exact match only, no dash-optionality.
        if let Some(native) = token.strip_prefix("--") {
            match native {
                "json" => plan.json = true,
                "status" => plan.status = true,
                "insecure-no-server-check" => plan.insecure_no_server_check = true,
                _ => return Err(EsFatal::unknown_switch(token)),
            }
            continue;
        }

        let (name, from_slash) = if let Some(stripped) = token.strip_prefix('-') {
            (stripped, false)
        } else if let Some(stripped) = token.strip_prefix('/') {
            (stripped, true)
        } else {
            query.push(token);
            continue;
        };

        match match_switch(name) {
            Some(action) => apply_switch(action, token, &mut rest, &mut plan)?,
            // es: unknown `/` tokens search for the text verbatim.
            None if from_slash => query.push(token),
            None => return Err(EsFatal::unknown_switch(token)),
        }
    }

    plan.query = query.join(" ");
    Ok(plan)
}

/// Resolves a prefix-stripped switch name against the full switch set.
/// Returns `None` when nothing matches (caller decides fatal vs fallthrough).
fn match_switch(name: &str) -> Option<SwitchAction> {
    for (canonical, action) in SIMPLE_SWITCHES {
        if switch_name_matches(name, canonical) {
            return Some(*action);
        }
    }
    for (alias, key) in SORT_KEYS {
        if let Some(spec) = match_sort_form(name, &format!("sort-{alias}"), *key) {
            return Some(SwitchAction::SortFixed(spec));
        }
    }
    None
}

/// Applies one matched switch, consuming its parameter from `rest` if it
/// takes one. `token` is the switch as the user typed it (for messages).
fn apply_switch(
    action: SwitchAction,
    token: &str,
    rest: &mut core::slice::Iter<'_, String>,
    plan: &mut EsPlan,
) -> Result<(), EsFatal> {
    match action {
        SwitchAction::Limit => {
            let value = take_param(rest, token)?;
            let limit: u32 = value
                .parse()
                .map_err(|_| EsFatal::bad_param(token, value, "a number"))?;
            plan.limit = Some(limit);
        }
        SwitchAction::Scope => plan.scope = Some(take_param(rest, token)?.to_owned()),
        SwitchAction::ExportCsv => plan.export_csv = Some(take_param(rest, token)?.to_owned()),
        SwitchAction::SortParam => {
            let value = take_param(rest, token)?;
            plan.sort = parse_sort_param(value)
                .ok_or_else(|| EsFatal::bad_param(token, value, "a sort key"))?;
        }
        SwitchAction::Column(column) => {
            // es `es_add_column`: remove an existing instance, then append,
            // so the last occurrence determines the column's position.
            plan.columns.retain(|existing| *existing != column);
            plan.columns.push(column);
        }
        SwitchAction::SortFixed(spec) => plan.sort = spec,
        SwitchAction::Utf8Bom => plan.bom = true,
        SwitchAction::NoUtf8Bom => plan.bom = false,
        SwitchAction::NoHeader => plan.header = false,
        SwitchAction::NoDoubleQuote => plan.double_quote = false,
        SwitchAction::MatchCase => plan.match_case = true,
    }
    Ok(())
}

/// Consumes the next token as a switch parameter, or fails with exit 4
/// naming the switch as the user typed it.
fn take_param<'a>(
    rest: &mut core::slice::Iter<'a, String>,
    token: &str,
) -> Result<&'a str, EsFatal> {
    rest.next()
        .map(String::as_str)
        .ok_or_else(|| EsFatal::missing_param(token))
}

/// Resolves a `-sort` parameter value (`name`, `dm`, `date-modified`, ...
/// optionally suffixed `-ascending` / `-descending`) into a [`SortSpec`].
/// Uses the same dash-optional matching as switch names.
fn parse_sort_param(value: &str) -> Option<SortSpec> {
    SORT_KEYS
        .iter()
        .find_map(|(alias, key)| match_sort_form(value, alias, *key))
}

/// Matches `input` against `base`, `base-ascending`, or `base-descending`
/// (interior dashes optional). Unsuffixed forms take the key's es default
/// direction ([`SortSpec::default_for`]).
fn match_sort_form(input: &str, base: &str, key: SortKey) -> Option<SortSpec> {
    if switch_name_matches(input, base) {
        return Some(SortSpec::default_for(key));
    }
    if switch_name_matches(input, &format!("{base}-ascending")) {
        return Some(SortSpec {
            key,
            dir: SortDir::Asc,
        });
    }
    if switch_name_matches(input, &format!("{base}-descending")) {
        return Some(SortSpec {
            key,
            dir: SortDir::Desc,
        });
    }
    None
}

/// es switch-name comparison (`es_check_param`): case-sensitive, and every
/// dash in the canonical name optionally consumes one dash from the input.
/// Input dashes anywhere else fail the match.
fn switch_name_matches(input: &str, canonical: &str) -> bool {
    let mut input_chars = input.chars().peekable();
    for expected in canonical.chars() {
        if expected == '-' {
            if input_chars.peek() == Some(&'-') {
                input_chars.next();
            }
        } else if input_chars.next() != Some(expected) {
            return false;
        }
    }
    input_chars.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(tokens: &[&str]) -> Result<EsPlan, EsFatal> {
        let args: Vec<String> = tokens.iter().map(ToString::to_string).collect();
        parse_argv(&args)
    }

    fn plan(tokens: &[&str]) -> EsPlan {
        parse(tokens).expect("expected a successful parse")
    }

    fn fatal(tokens: &[&str]) -> EsFatal {
        parse(tokens).expect_err("expected a fatal parse error")
    }

    use proptest::prelude::*;

    proptest! {
        /// The argv parser is total: for ANY input it returns Ok or a fatal
        /// `EsFatal`, never panicking (its documented contract).
        #[test]
        fn parse_argv_never_panics_on_arbitrary_input(
            args in proptest::collection::vec(".*", 0..12),
        ) {
            let _ = parse_argv(&args);
        }

        /// Flag-shaped tokens (leading `-`/`/` plus arbitrary text, missing
        /// switch parameters, empty tokens) also never panic.
        #[test]
        fn parse_argv_never_panics_on_flaglike_input(
            args in proptest::collection::vec(
                prop_oneof!["-[a-zA-Z-]{0,16}", "/[a-zA-Z-]{0,16}", "[^ ]{0,16}"],
                0..12,
            ),
        ) {
            let _ = parse_argv(&args);
        }
    }

    #[test]
    fn empty_argv_yields_default_plan() {
        let parsed = plan(&[]);
        assert_eq!(parsed, EsPlan::default());
        assert_eq!(parsed.query, "");
        assert_eq!(parsed.sort, SortSpec::default());
        assert!(parsed.bom);
        assert!(parsed.header);
        assert!(parsed.double_quote);
        assert!(!parsed.match_case);
    }

    #[test]
    fn app_reference_invocation_full_plan() {
        let parsed = plan(&[
            "-path",
            "C:\\some dir",
            "report",
            "-n",
            "200",
            "-size",
            "-dm",
            "-sort-path",
            "-export-csv",
            "C:\\tmp\\out.csv",
        ]);
        assert_eq!(
            parsed,
            EsPlan {
                query: "report".to_string(),
                scope: Some("C:\\some dir".to_string()),
                limit: Some(200),
                columns: vec![EsColumn::Size, EsColumn::DateModified],
                sort: SortSpec {
                    key: SortKey::Path,
                    dir: SortDir::Asc,
                },
                export_csv: Some("C:\\tmp\\out.csv".to_string()),
                bom: true,
                header: true,
                double_quote: true,
                match_case: false,
                json: false,
                status: false,
                insecure_no_server_check: false,
            }
        );
    }

    #[test]
    fn interior_dashes_are_optional_everywhere() {
        assert_eq!(
            plan(&["-sortpath"]).sort,
            SortSpec::default_for(SortKey::Path)
        );
        assert_eq!(plan(&["-maxresults", "7"]).limit, Some(7));
        assert!(!plan(&["-noutf8bom"]).bom);
        assert!(!plan(&["-nodoublequote"]).double_quote);
        assert_eq!(
            plan(&["-datemodified"]).columns,
            vec![EsColumn::DateModified]
        );
        assert_eq!(
            plan(&["-sortpathascending"]).sort,
            SortSpec {
                key: SortKey::Path,
                dir: SortDir::Asc,
            }
        );
        assert_eq!(
            plan(&["-sortdatemodifieddescending"]).sort,
            SortSpec {
                key: SortKey::DateModified,
                dir: SortDir::Desc,
            }
        );
        // Partial omission is fine too: any subset of dashes may be dropped.
        assert!(!plan(&["-no-utf8bom"]).bom);
        assert_eq!(plan(&["-max-results", "3"]).limit, Some(3));
    }

    #[test]
    fn switch_matching_is_case_sensitive() {
        assert_eq!(fatal(&["-SORT-PATH"]).exit_code, 6);
        assert_eq!(fatal(&["-N", "5"]).exit_code, 6);
    }

    #[test]
    fn input_dash_where_canonical_has_none_is_unknown() {
        assert_eq!(fatal(&["-d-m"]).exit_code, 6);
        assert_eq!(fatal(&["-si-ze"]).exit_code, 6);
        assert_eq!(fatal(&["-no--header"]).exit_code, 6);
    }

    #[test]
    fn unknown_dash_switch_is_exit_6_with_token() {
        let err = fatal(&["-zzz"]);
        assert_eq!(err.exit_code, 6);
        assert!(err.message.contains("-zzz"), "message was: {}", err.message);
    }

    #[test]
    fn slash_token_without_match_falls_through_to_query() {
        assert_eq!(plan(&["/nomatch"]).query, "/nomatch");
        assert_eq!(plan(&["report", "/downloads"]).query, "report /downloads");
    }

    #[test]
    fn slash_token_with_match_is_a_switch() {
        // Research: es_check_param treats `-` and `/` prefixes identically,
        // so /n is the -n switch, not search text.
        let parsed = plan(&["/n", "50"]);
        assert_eq!(parsed.limit, Some(50));
        assert_eq!(parsed.query, "");
        // A matched `/` switch with a missing parameter is exit 4 like `-`.
        assert_eq!(fatal(&["/path"]).exit_code, 4);
    }

    #[test]
    fn missing_parameter_is_exit_4_naming_the_switch() {
        for switch in ["-n", "-path", "-export-csv", "-sort", "-maxresults"] {
            let err = fatal(&[switch]);
            assert_eq!(err.exit_code, 4, "switch: {switch}");
            assert!(
                err.message.contains(switch),
                "message for {switch} was: {}",
                err.message
            );
        }
    }

    #[test]
    fn non_numeric_count_is_exit_4() {
        assert_eq!(fatal(&["-n", "abc"]).exit_code, 4);
        assert_eq!(fatal(&["-n", "-5"]).exit_code, 4);
        // Overflowing u32 is a bad parameter, not a silent wrap.
        assert_eq!(fatal(&["-n", "4294967296"]).exit_code, 4);
    }

    #[test]
    fn sort_param_defaults_direction_per_key() {
        assert_eq!(
            plan(&["-sort", "dm"]).sort,
            SortSpec {
                key: SortKey::DateModified,
                dir: SortDir::Desc,
            }
        );
        assert_eq!(
            plan(&["-sort", "size"]).sort,
            SortSpec {
                key: SortKey::Size,
                dir: SortDir::Desc,
            }
        );
        assert_eq!(
            plan(&["-sort", "name"]).sort,
            SortSpec {
                key: SortKey::Name,
                dir: SortDir::Asc,
            }
        );
        assert_eq!(
            plan(&["-sort", "path"]).sort,
            SortSpec {
                key: SortKey::Path,
                dir: SortDir::Asc,
            }
        );
    }

    #[test]
    fn sort_param_with_direction_suffix() {
        assert_eq!(
            plan(&["-sort", "name-descending"]).sort,
            SortSpec {
                key: SortKey::Name,
                dir: SortDir::Desc,
            }
        );
        assert_eq!(
            plan(&["-sort", "date-modified-ascending"]).sort,
            SortSpec {
                key: SortKey::DateModified,
                dir: SortDir::Asc,
            }
        );
        // The parameter uses the same dash-optional matching as switch names.
        assert_eq!(
            plan(&["-sort", "namedescending"]).sort,
            SortSpec {
                key: SortKey::Name,
                dir: SortDir::Desc,
            }
        );
        assert_eq!(
            plan(&["-sort", "datemodified"]).sort,
            SortSpec {
                key: SortKey::DateModified,
                dir: SortDir::Desc,
            }
        );
    }

    #[test]
    fn sort_param_unknown_key_is_exit_4() {
        let err = fatal(&["-sort", "bogus"]);
        assert_eq!(err.exit_code, 4);
        assert!(
            err.message.contains("bogus"),
            "message was: {}",
            err.message
        );
    }

    #[test]
    fn combined_sort_switches() {
        assert_eq!(
            plan(&["-sort-name"]).sort,
            SortSpec::default_for(SortKey::Name)
        );
        assert_eq!(
            plan(&["-sort-size"]).sort,
            SortSpec {
                key: SortKey::Size,
                dir: SortDir::Desc,
            }
        );
        assert_eq!(
            plan(&["-sort-dm"]).sort,
            SortSpec {
                key: SortKey::DateModified,
                dir: SortDir::Desc,
            }
        );
        assert_eq!(
            plan(&["-sort-date-modified"]).sort,
            SortSpec {
                key: SortKey::DateModified,
                dir: SortDir::Desc,
            }
        );
        assert_eq!(
            plan(&["-sort-dm-descending"]).sort,
            SortSpec {
                key: SortKey::DateModified,
                dir: SortDir::Desc,
            }
        );
        assert_eq!(
            plan(&["-sort-size-ascending"]).sort,
            SortSpec {
                key: SortKey::Size,
                dir: SortDir::Asc,
            }
        );
    }

    #[test]
    fn last_sort_switch_wins() {
        assert_eq!(
            plan(&["-sort-path", "-sort", "size"]).sort,
            SortSpec {
                key: SortKey::Size,
                dir: SortDir::Desc,
            }
        );
        assert_eq!(
            plan(&["-sort", "size", "-sortpath"]).sort,
            SortSpec {
                key: SortKey::Path,
                dir: SortDir::Asc,
            }
        );
    }

    #[test]
    fn query_tokens_join_with_single_spaces_around_interleaved_flags() {
        let parsed = plan(&["foo", "-size", "bar", "-n", "5", "baz qux"]);
        assert_eq!(parsed.query, "foo bar baz qux");
        assert_eq!(parsed.limit, Some(5));
        assert_eq!(parsed.columns, vec![EsColumn::Size]);
    }

    #[test]
    fn columns_dedupe_and_reorder_like_es() {
        assert_eq!(plan(&["-size", "-size"]).columns, vec![EsColumn::Size]);
        // es removes the existing instance then appends: last occurrence
        // determines position.
        assert_eq!(
            plan(&["-size", "-dm", "-size"]).columns,
            vec![EsColumn::DateModified, EsColumn::Size]
        );
    }

    #[test]
    fn native_namespace_flags() {
        assert!(plan(&["--json"]).json);
        assert!(plan(&["--status"]).status);
        assert!(plan(&["--insecure-no-server-check"]).insecure_no_server_check);
        let all = plan(&["--json", "--status"]);
        assert!(all.json && all.status);
    }

    #[test]
    fn native_namespace_unknown_is_exit_6() {
        let err = fatal(&["--bogus"]);
        assert_eq!(err.exit_code, 6);
        assert!(
            err.message.contains("--bogus"),
            "message was: {}",
            err.message
        );
        // Native names are exact: no dash-optionality in the -- namespace.
        assert_eq!(fatal(&["--insecureno-server-check"]).exit_code, 6);
    }

    #[test]
    fn all_dash_tokens_are_search_text() {
        assert_eq!(plan(&["-", "--", "---"]).query, "- -- ---");
    }

    #[test]
    fn utf8_bom_switches() {
        assert!(plan(&["-utf8-bom"]).bom, "accepted no-op vs goz default");
        assert!(!plan(&["-no-utf8-bom"]).bom);
        assert!(plan(&["-no-utf8-bom", "-utf8-bom"]).bom, "last flag wins");
    }

    #[test]
    fn header_and_double_quote_suppression() {
        assert!(!plan(&["-no-header"]).header);
        assert!(!plan(&["-no-double-quote"]).double_quote);
    }

    #[test]
    fn match_case_aliases() {
        assert!(plan(&["-case"]).match_case);
        assert!(plan(&["-match-case"]).match_case);
        assert!(plan(&["-matchcase"]).match_case);
    }

    #[test]
    fn scope_is_taken_verbatim() {
        // Absolutization is the CLI's job; the core keeps the raw value.
        assert_eq!(
            plan(&["-path", "rel\\dir"]).scope,
            Some("rel\\dir".to_string())
        );
    }

    #[test]
    fn fatal_display_is_the_message() {
        let err = fatal(&["-zzz"]);
        assert_eq!(format!("{err}"), err.message);
    }
}
