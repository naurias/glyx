use std::collections::BTreeMap;

use similar::{DiffOp, TextDiff};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HunkKind {
    Same,
    TheirsOnly,
    OursOnly,
    Conflict,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hunk {
    pub base: Vec<String>,
    pub theirs: Vec<String>,
    pub ours: Vec<String>,
    pub kind: HunkKind,
    pub secret: bool,
}

#[derive(Debug, Clone)]
pub enum Pick {
    Theirs,
    Ours,
    Custom(String),
}

fn changed_intervals(old: &str, new: &str) -> Vec<(usize, usize, Vec<String>)> {
    let diff = TextDiff::from_lines(old, new);
    let mut out = Vec::new();
    for op in diff.ops() {
        match *op {
            DiffOp::Equal { .. } => {}
            DiffOp::Delete {
                old_index, old_len, ..
            } => {
                out.push((old_index, old_index + old_len, Vec::new()));
            }
            DiffOp::Insert {
                old_index,
                new_index,
                new_len,
            } => {
                out.push((old_index, old_index, new_lines(&diff, new_index, new_len)));
            }
            DiffOp::Replace {
                old_index,
                old_len,
                new_index,
                new_len,
            } => {
                out.push((
                    old_index,
                    old_index + old_len,
                    new_lines(&diff, new_index, new_len),
                ));
            }
        }
    }
    out
}

fn new_lines(diff: &TextDiff<str>, start: usize, len: usize) -> Vec<String> {
    diff.new_slices()
        .get(start..start + len)
        .unwrap_or(&[])
        .iter()
        .map(|s| {
            s.strip_suffix("\r\n")
                .or_else(|| s.strip_suffix('\n'))
                .unwrap_or(s)
                .to_owned()
        })
        .collect()
}

fn overlaps(s: usize, e: usize, has_lines: bool, begin: usize, end: usize) -> bool {
    if s < end && e > begin {
        return true;
    }
    if s == begin && e >= begin {
        return true;
    }
    s == e && has_lines && s >= begin && s <= end
}

fn touches_spans(lines: &[String], spans: &[String]) -> bool {
    lines.iter().any(|line| {
        spans
            .iter()
            .any(|span| !span.is_empty() && line.contains(span))
    })
}

pub fn diff_hunks(base: &str, theirs: &str, ours: &str, vault_spans: &[String]) -> Vec<Hunk> {
    let base_lines: Vec<String> = base.lines().map(str::to_owned).collect();
    let total = base_lines.len();
    let mut theirs_changes = changed_intervals(base, theirs);
    let mut ours_changes = changed_intervals(base, ours);
    theirs_changes.sort();
    ours_changes.sort();
    let mut hunks = Vec::new();
    let mut cursor = 0;
    loop {
        let pending = |list: &[(usize, usize, Vec<String>)]| {
            list.iter()
                .find(|(s, e, lines)| {
                    *e > cursor || (*s == *e && !lines.is_empty() && *s >= cursor)
                })
                .map(|(s, _, _)| *s)
        };
        let start = match (pending(&theirs_changes), pending(&ours_changes)) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => {
                if cursor < total {
                    hunks.push(Hunk {
                        base: base_lines[cursor..].to_vec(),
                        theirs: base_lines[cursor..].to_vec(),
                        ours: base_lines[cursor..].to_vec(),
                        kind: HunkKind::Same,
                        secret: false,
                    });
                }
                break;
            }
        };
        let begin = start.max(cursor);
        if begin > cursor {
            hunks.push(Hunk {
                base: base_lines[cursor..begin].to_vec(),
                theirs: base_lines[cursor..begin].to_vec(),
                ours: base_lines[cursor..begin].to_vec(),
                kind: HunkKind::Same,
                secret: false,
            });
        }
        let mut end = begin;
        loop {
            let mut grew = false;
            for changes in [&theirs_changes, &ours_changes] {
                for (s, e, lines) in changes {
                    if overlaps(*s, *e, !lines.is_empty(), begin, end) && *e > end {
                        end = *e;
                        grew = true;
                    }
                }
            }
            if !grew {
                break;
            }
        }
        let mut theirs_lines: Option<Vec<String>> = None;
        let mut ours_lines: Option<Vec<String>> = None;
        for (s, e, lines) in &theirs_changes {
            if overlaps(*s, *e, !lines.is_empty(), begin, end) {
                theirs_lines
                    .get_or_insert_with(Vec::new)
                    .extend(lines.iter().cloned());
            }
        }
        for (s, e, lines) in &ours_changes {
            if overlaps(*s, *e, !lines.is_empty(), begin, end) {
                ours_lines
                    .get_or_insert_with(Vec::new)
                    .extend(lines.iter().cloned());
            }
        }
        theirs_changes.retain(|(s, e, lines)| !overlaps(*s, *e, !lines.is_empty(), begin, end));
        ours_changes.retain(|(s, e, lines)| !overlaps(*s, *e, !lines.is_empty(), begin, end));
        let base_slice = base_lines[begin..end].to_vec();
        let theirs_slice = theirs_lines.unwrap_or_else(|| base_slice.clone());
        let ours_slice = ours_lines.unwrap_or_else(|| base_slice.clone());
        let theirs_differs = theirs_slice != base_slice;
        let ours_differs = ours_slice != base_slice;
        let (kind, base_slice) = match (theirs_differs, ours_differs) {
            (false, false) => (HunkKind::Same, base_slice),
            (true, false) => (HunkKind::TheirsOnly, base_slice),
            (false, true) => (HunkKind::OursOnly, base_slice),
            (true, true) if theirs_slice == ours_slice => (HunkKind::Same, theirs_slice.clone()),
            (true, true) => (HunkKind::Conflict, base_slice),
        };
        let secret = touches_spans(&base_slice, vault_spans)
            || touches_spans(&theirs_slice, vault_spans)
            || touches_spans(&ours_slice, vault_spans);
        hunks.push(Hunk {
            base: base_slice,
            theirs: theirs_slice,
            ours: ours_slice,
            kind,
            secret,
        });
        cursor = end;
    }
    hunks
}

pub fn apply_hunks(
    hunks: &[Hunk],
    picks: &BTreeMap<usize, Pick>,
    trailing_newline: bool,
) -> Result<String, usize> {
    let mut out = Vec::new();
    for (idx, hunk) in hunks.iter().enumerate() {
        match hunk.kind {
            HunkKind::Same => out.extend(hunk.base.iter().cloned()),
            HunkKind::TheirsOnly => out.extend(hunk.theirs.iter().cloned()),
            HunkKind::OursOnly => out.extend(hunk.ours.iter().cloned()),
            HunkKind::Conflict => match picks.get(&idx) {
                Some(Pick::Theirs) => out.extend(hunk.theirs.iter().cloned()),
                Some(Pick::Ours) => out.extend(hunk.ours.iter().cloned()),
                Some(Pick::Custom(text)) => out.extend(text.lines().map(str::to_owned)),
                None => return Err(idx),
            },
        }
    }
    let mut text = out.join("\n");
    if trailing_newline && !text.is_empty() {
        text.push('\n');
    }
    Ok(text)
}

#[must_use]
pub fn conflict_indexes(hunks: &[Hunk]) -> Vec<usize> {
    hunks
        .iter()
        .enumerate()
        .filter(|(_, h)| h.kind == HunkKind::Conflict)
        .map(|(i, _)| i)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn clean_sides_resolve() {
        let base = "a\nb\nc\n";
        let theirs = "a\nB\nc\n";
        let ours = "a\nb\nC\n";
        let hunks = diff_hunks(base, theirs, ours, &[]);
        assert!(conflict_indexes(&hunks).is_empty());
        let out = apply_hunks(&hunks, &BTreeMap::new(), true).expect("apply");
        assert_eq!(out, "a\nB\nC\n");
    }

    #[test]
    fn identical_sides_stay_quiet() {
        let base = "a\nb\n";
        let hunks = diff_hunks(base, base, base, &[]);
        assert!(hunks.iter().all(|h| h.kind == HunkKind::Same));
        assert!(conflict_indexes(&hunks).is_empty());
    }

    #[test]
    fn same_change_both_sides_is_quiet() {
        let base = "a\nb\n";
        let both = "a\nB\n";
        let hunks = diff_hunks(base, both, both, &[]);
        assert!(conflict_indexes(&hunks).is_empty());
        let out = apply_hunks(&hunks, &BTreeMap::new(), true).expect("apply");
        assert_eq!(out, both);
    }

    #[test]
    fn true_conflict_needs_pick() {
        let base = "a\nb\nc\n";
        let theirs = "a\nB1\nc\n";
        let ours = "a\nB2\nc\n";
        let hunks = diff_hunks(base, theirs, ours, &[]);
        let conflicts = conflict_indexes(&hunks);
        assert_eq!(conflicts.len(), 1);
        assert!(apply_hunks(&hunks, &BTreeMap::new(), true).is_err());
        let mut picks = BTreeMap::new();
        picks.insert(conflicts[0], Pick::Theirs);
        assert_eq!(apply_hunks(&hunks, &picks, true).expect("apply"), theirs);
        picks.insert(conflicts[0], Pick::Ours);
        assert_eq!(apply_hunks(&hunks, &picks, true).expect("apply"), ours);
        picks.insert(conflicts[0], Pick::Custom("B3".to_owned()));
        assert_eq!(
            apply_hunks(&hunks, &picks, true).expect("apply"),
            "a\nB3\nc\n"
        );
    }

    #[test]
    fn secret_hunk_flagged() {
        let base = "pass=__ENC__\nname=x\n";
        let theirs = "pass=__ENC__\nname=y\n";
        let ours = "pass=s3cret\nname=x\n";
        let hunks = diff_hunks(base, theirs, ours, &spans(&["__ENC__", "s3cret"]));
        assert!(conflict_indexes(&hunks).is_empty());
        assert!(hunks.iter().any(|h| h.secret));
        let out = apply_hunks(&hunks, &BTreeMap::new(), true).expect("apply");
        assert_eq!(out, "pass=s3cret\nname=y\n");
    }

    #[test]
    fn trailing_insert_both_sides() {
        let base = "a\n";
        let theirs = "a\nt1\n";
        let ours = "a\no1\n";
        let hunks = diff_hunks(base, theirs, ours, &[]);
        assert_eq!(conflict_indexes(&hunks).len(), 1);
        let base2 = "a\n";
        let hunks = diff_hunks(base2, base2, ours, &[]);
        assert!(conflict_indexes(&hunks).is_empty());
        let out = apply_hunks(&hunks, &BTreeMap::new(), true).expect("apply");
        assert_eq!(out, ours);
    }

    #[test]
    fn no_markers_ever_written() {
        let base = "a\n";
        let theirs = "b\n";
        let ours = "c\n";
        let hunks = diff_hunks(base, theirs, ours, &[]);
        let mut picks = BTreeMap::new();
        for idx in conflict_indexes(&hunks) {
            picks.insert(idx, Pick::Theirs);
        }
        let out = apply_hunks(&hunks, &picks, true).expect("apply");
        assert!(!out.contains("<<<<<<<") && !out.contains(">>>>>>>"));
    }
}
