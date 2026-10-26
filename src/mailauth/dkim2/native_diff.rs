// SPDX-FileCopyrightText: 2026 Workglen contributors
// SPDX-License-Identifier: Apache-2.0
// First-party bounded shortest-edit search. Indices are zero-based; deletions
// need no instruction because a recipe only describes the reconstructed output.

pub(crate) const MAX_ITEMS: usize = 200_000;
const MAX_DISTANCE: usize = 512;
const MAX_WORK: usize = 2_000_000;
const MAX_COMPARE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Edit {
    Copy { start: usize, len: usize },
    Insert { start: usize, len: usize },
}

pub(crate) struct Budget {
    work: usize,
    bytes: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            work: MAX_WORK,
            bytes: MAX_COMPARE_BYTES,
        }
    }
}

impl Budget {
    fn charge(&mut self, work: usize, bytes: usize) -> Option<()> {
        // Exhaust either allowance permanently; callers share this budget over
        // all header groups and the body of one message pair.
        if work > self.work || bytes > self.bytes {
            self.work = 0;
            self.bytes = 0;
            return None;
        }
        self.work -= work;
        self.bytes -= bytes;
        Some(())
    }

    fn equal(&mut self, a: &[u8], b: &[u8]) -> Option<bool> {
        self.charge(1, if a.len() == b.len() { a.len() } else { 0 })?;
        Some(a == b)
    }
}

fn append(out: &mut Vec<Edit>, edit: Edit) {
    match (out.last_mut(), edit) {
        (
            Some(Edit::Copy { start, len }),
            Edit::Copy {
                start: next,
                len: more,
            },
        )
        | (
            Some(Edit::Insert { start, len }),
            Edit::Insert {
                start: next,
                len: more,
            },
        ) if *start + *len == next => *len += more,
        _ => out.push(edit),
    }
}

/// Returns a shortest insert/delete script, or None when the shared budget or
/// search-distance limit is reached. At most 513 * 1027 isize cells are retained
/// for traceback (about 4.1 MiB on 64-bit hosts), independent of message size.
pub(crate) fn diff(old: &[&[u8]], new: &[&[u8]], budget: &mut Budget) -> Option<Vec<Edit>> {
    if old.len().checked_add(new.len())? > MAX_ITEMS {
        return None;
    }
    let mut prefix = 0;
    while prefix < old.len().min(new.len()) && budget.equal(old[prefix], new[prefix])? {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < old.len().min(new.len()) - prefix
        && budget.equal(old[old.len() - suffix - 1], new[new.len() - suffix - 1])?
    {
        suffix += 1;
    }
    let a = &old[prefix..old.len() - suffix];
    let b = &new[prefix..new.len() - suffix];
    let mut out = Vec::new();
    if prefix > 0 {
        append(
            &mut out,
            Edit::Copy {
                start: 0,
                len: prefix,
            },
        );
    }
    if a.is_empty() {
        if !b.is_empty() {
            append(
                &mut out,
                Edit::Insert {
                    start: prefix,
                    len: b.len(),
                },
            );
        }
    } else if !b.is_empty() {
        let limit = (a.len() + b.len()).min(MAX_DISTANCE);
        if a.len().abs_diff(b.len()) > limit {
            return None;
        }
        let offset = limit as isize + 1;
        let width = 2 * limit + 3;
        let mut frontier = vec![-1isize; width];
        frontier[(offset + 1) as usize] = 0;
        let mut trace: Vec<Vec<isize>> = Vec::new();
        let mut distance = None;
        'search: for d in 0..=limit {
            let d = d as isize;
            for k in (-d..=d).step_by(2) {
                budget.charge(1, 0)?;
                let slot = (offset + k) as usize;
                let mut x = if k == -d || (k != d && frontier[slot - 1] < frontier[slot + 1]) {
                    frontier[slot + 1]
                } else {
                    frontier[slot - 1] + 1
                };
                let mut y = x - k;
                if x < 0 || y < 0 {
                    continue;
                }
                while (x as usize) < a.len()
                    && (y as usize) < b.len()
                    && budget.equal(a[x as usize], b[y as usize])?
                {
                    x += 1;
                    y += 1;
                }
                frontier[slot] = x;
                if x == a.len() as isize && y == b.len() as isize {
                    distance = Some(d as usize);
                    break 'search;
                }
            }
            budget.charge(width, 0)?;
            trace.push(frontier.clone());
        }
        let distance = distance?;
        let (mut x, mut y) = (a.len() as isize, b.len() as isize);
        let mut reversed = Vec::new();
        for d in (1..=distance).rev() {
            let previous = &trace[d - 1];
            let k = x - y;
            let slot = (offset + k) as usize;
            let prev_k = if k == -(d as isize)
                || (k != d as isize && previous[slot - 1] < previous[slot + 1])
            {
                k + 1
            } else {
                k - 1
            };
            let prev_x = previous[(offset + prev_k) as usize];
            let prev_y = prev_x - prev_k;
            let snake = (x - prev_x).min(y - prev_y);
            if snake > 0 {
                x -= snake;
                reversed.push(Edit::Copy {
                    start: prefix + x as usize,
                    len: snake as usize,
                });
            }
            if x == prev_x {
                reversed.push(Edit::Insert {
                    start: prefix + prev_y as usize,
                    len: 1,
                });
            }
            x = prev_x;
            y = prev_y;
        }
        if x > 0 {
            reversed.push(Edit::Copy {
                start: prefix,
                len: x as usize,
            });
        }
        for edit in reversed.into_iter().rev() {
            append(&mut out, edit);
        }
    }
    if suffix > 0 {
        append(
            &mut out,
            Edit::Copy {
                start: old.len() - suffix,
                len: suffix,
            },
        );
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_and_work_budgets_are_shared_and_fail_closed() {
        let mut budget = Budget { work: 2, bytes: 4 };
        assert_eq!(budget.equal(b"12345", b"12345"), None);
        assert_eq!(budget.equal(b"", b""), None);
        let mut budget = Budget {
            work: 1,
            bytes: 100,
        };
        assert_eq!(budget.equal(b"a", b"a"), Some(true));
        assert_eq!(budget.equal(b"a", b"a"), None);
    }

    #[test]
    fn distance_and_item_caps_are_enforced() {
        let a = vec![b"a".as_slice(); MAX_DISTANCE / 2];
        let b = vec![b"b".as_slice(); MAX_DISTANCE / 2];
        assert!(diff(&a, &b, &mut Budget::default()).is_some());
        let a = vec![b"a".as_slice(); MAX_DISTANCE / 2 + 1];
        let b = vec![b"b".as_slice(); MAX_DISTANCE / 2 + 1];
        assert!(diff(&a, &b, &mut Budget::default()).is_none());
        let old = vec![b"a".as_slice(); 600];
        let new = vec![b"b".as_slice(); 600];
        assert!(diff(&old, &new, &mut Budget::default()).is_none());
        let huge = vec![b"".as_slice(); MAX_ITEMS + 1];
        assert!(diff(&huge, &[], &mut Budget::default()).is_none());
    }
}
