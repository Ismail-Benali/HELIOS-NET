//! Aho-Corasick multi-pattern automaton.
//!
//! Single-pass, case-insensitive (ASCII) multi-pattern search. This replaces the
//! previous naive `text.contains(needle)` loop, which was O(patterns * text).
//!
//! Case folding is deliberately ASCII-only (A-Z -> a-z) so the result is
//! byte-identical to the C core and the Python fallback. Using Unicode
//! `to_lowercase()` would make Rust disagree with the other two engines on any
//! non-ASCII banner, which is exactly the divergence the native/fallback parity
//! test guards against.

/// A single compiled pattern.
pub struct Pattern {
    /// Index into the owning automaton's pattern table.
    pub id: u32,
    /// Lowercased ASCII needle used for matching.
    pub needle: Vec<u8>,
    /// Original text as supplied by the caller (the reported label).
    pub label: String,
}

/// One pattern match within a scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// Pattern id, index into `AhoCorasick::patterns`.
    pub pattern: u32,
    /// Byte offset one past the final matched byte.
    pub end: usize,
}

/// A trie node with sparse, sorted edges.
struct Node {
    /// `(byte, child)` pairs kept sorted so lookup is a binary search.
    /// A target of `0` is a reserved placeholder; no real edge points at the root.
    edges: Vec<(u8, u32)>,
    /// Failure link.
    fail: u32,
    /// Pattern ids terminating exactly at this node.
    own: Vec<u32>,
    /// Pattern ids reaching this node through failure links (filled by `build`).
    output: Vec<u32>,
}

impl Node {
    fn new() -> Self {
        Node {
            edges: Vec::new(),
            fail: 0,
            own: Vec::new(),
            output: Vec::new(),
        }
    }

    fn lookup(&self, b: u8) -> Option<u32> {
        self.edges
            .binary_search_by_key(&b, |&(k, _)| k)
            .ok()
            .map(|idx| self.edges[idx].1)
    }
}

/// A compiled multi-pattern matcher.
pub struct AhoCorasick {
    nodes: Vec<Node>,
    patterns: Vec<Pattern>,
    built: bool,
}

impl Default for AhoCorasick {
    fn default() -> Self {
        Self::new()
    }
}

impl AhoCorasick {
    pub fn new() -> Self {
        AhoCorasick {
            nodes: vec![Node::new()],
            patterns: Vec::new(),
            built: false,
        }
    }

    /// Folds A-Z to a-z and leaves every other byte untouched.
    #[inline]
    pub fn fold_byte(b: u8) -> u8 {
        if b.is_ascii_uppercase() {
            b + 32
        } else {
            b
        }
    }

    /// Adds a pattern. `label` is reported verbatim; matching is case-insensitive.
    ///
    /// Empty and whitespace-only labels are ignored, and a duplicate needle is
    /// stored once so results never repeat a signature.
    pub fn add(&mut self, label: &str) -> bool {
        // An empty or whitespace-only pattern is rejected, and anything else is
        // used verbatim, which is what the C core's signature parser does: it
        // trims the line and then splits at the first tab, leaving the pattern
        // itself untouched.
        //
        // Trimming here quietly moved every pattern that began or ended in a
        // space. ' SSH' became 'SSH', so this core reported a hit one byte later
        // than the C core and matched text the C core rejected. The two cores
        // disagreed on the same signature file, and nothing compared them.
        if label.is_empty() || label.chars().all(char::is_whitespace) {
            return false;
        }
        let needle: Vec<u8> = label.bytes().map(AhoCorasick::fold_byte).collect();
        if self.patterns.iter().any(|p| p.needle == needle) {
            return false;
        }

        let id = self.patterns.len() as u32;
        let mut cur = 0usize;

        for &b in &needle {
            match self.nodes[cur].edges.binary_search_by_key(&b, |&(k, _)| k) {
                // Edge slot exists; materialise a node if it is still a placeholder.
                Ok(idx) => {
                    let target = self.nodes[cur].edges[idx].1;
                    if target == 0 {
                        self.nodes.push(Node::new());
                        let child = (self.nodes.len() - 1) as u32;
                        self.nodes[cur].edges[idx].1 = child;
                        cur = self.nodes.len() - 1;
                    } else {
                        cur = target as usize;
                    }
                }
                // No edge yet: append a fresh child in sorted position.
                Err(idx) => {
                    self.nodes.push(Node::new());
                    let child = (self.nodes.len() - 1) as u32;
                    self.nodes[cur].edges.insert(idx, (b, child));
                    cur = self.nodes.len() - 1;
                }
            }
        }

        self.nodes[cur].own.push(id);
        self.patterns.push(Pattern {
            id,
            needle,
            label: label.to_string(),
        });
        self.built = false;
        true
    }

    /// Number of distinct compiled patterns.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Builds failure links and the propagated output lists.
    pub fn build(&mut self) {
        if self.built {
            return;
        }
        for node in &mut self.nodes {
            node.fail = 0;
            node.output.clear();
        }

        // Breadth-first, so a node's failure link is always resolved before use.
        let mut queue: Vec<u32> = Vec::new();
        let root_children: Vec<u32> = self.nodes[0].edges.iter().map(|&(_, c)| c).collect();
        for child in root_children {
            self.nodes[child as usize].fail = 0;
            queue.push(child);
        }

        let mut head = 0usize;
        while head < queue.len() {
            let u = queue[head];
            head += 1;
            let f0 = self.nodes[u as usize].fail;

            let edges = self.nodes[u as usize].edges.clone();
            for (b, v) in edges {
                let mut f = f0;
                while f != 0 && self.nodes[f as usize].lookup(b).is_none() {
                    f = self.nodes[f as usize].fail;
                }
                self.nodes[v as usize].fail = match self.nodes[f as usize].lookup(b) {
                    Some(next) if next != v => next,
                    _ => 0,
                };
                queue.push(v);
            }
        }

        // output[v] = own[v] + output[fail[v]]
        //
        // This MUST run in breadth-first order, not index order. Node indices
        // follow pattern-insertion order, which is unrelated to depth, so
        // `output[fail[v]]` is not necessarily computed yet if we walk 1..len.
        // A failure link always points to a strictly shallower node, so the BFS
        // queue is exactly the order this recurrence requires.
        for &i in &queue {
            let mut merged = self.nodes[i as usize].own.clone();
            let fail = self.nodes[i as usize].fail as usize;
            let inherited = self.nodes[fail].output.clone();
            merged.extend(inherited);
            merged.sort_unstable();
            merged.dedup();
            self.nodes[i as usize].output = merged;
        }

        self.built = true;
    }

    /// Scans `text`, appending every match to `out` in end-offset order.
    pub fn find_all(&self, text: &[u8], out: &mut Vec<Hit>) {
        out.clear();
        if self.patterns.is_empty() {
            return;
        }
        let mut cur = 0usize;
        for (i, &raw) in text.iter().enumerate() {
            let b = AhoCorasick::fold_byte(raw);
            while cur != 0 && self.nodes[cur].lookup(b).is_none() {
                cur = self.nodes[cur].fail as usize;
            }
            cur = match self.nodes[cur].lookup(b) {
                Some(next) => next as usize,
                None => 0,
            };
            for &pid in &self.nodes[cur].output {
                out.push(Hit {
                    pattern: pid,
                    end: i + 1,
                });
            }
        }
    }

    /// Byte offset where `pattern` starts for a match ending at `end`.
    pub fn start_offset(&self, pattern: u32, end: usize) -> usize {
        let len = self
            .patterns
            .get(pattern as usize)
            .map(|p| p.needle.len())
            .unwrap_or(0);
        end.saturating_sub(len)
    }

    pub fn label(&self, id: u32) -> &str {
        self.patterns
            .get(id as usize)
            .map(|p| p.label.as_str())
            .unwrap_or("")
    }

    /// Scans `text` and returns `(label, start_offset)` pairs.
    pub fn scan(&self, text: &[u8]) -> Vec<(String, usize)> {
        let mut hits = Vec::new();
        let mut buffer = Vec::new();
        self.find_all(text, &mut buffer);
        hits.reserve(buffer.len());
        for hit in buffer {
            hits.push((
                self.label(hit.pattern).to_string(),
                self.start_offset(hit.pattern, hit.end),
            ));
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ac(patterns: &[&str]) -> AhoCorasick {
        let mut a = AhoCorasick::new();
        for p in patterns {
            a.add(p);
        }
        a.build();
        a
    }

    fn labels(hits: &[(String, usize)]) -> Vec<&str> {
        hits.iter().map(|(l, _)| l.as_str()).collect()
    }

    fn sorted(mut hits: Vec<(String, usize)>) -> Vec<(String, usize)> {
        hits.sort();
        hits
    }

    #[test]
    fn matches_single_pattern() {
        let a = ac(&["nginx"]);
        let hits = a.scan(b"Server: nginx/1.24.0");
        assert_eq!(labels(&hits), vec!["nginx"]);
        assert_eq!(hits[0].1, 8);
    }

    #[test]
    fn matching_is_ascii_case_insensitive() {
        let a = ac(&["OpenSSH", "NGINX"]);
        assert_eq!(
            labels(&a.scan(b"server: NGINX and openssh")),
            vec!["NGINX", "OpenSSH"]
        );
        assert_eq!(labels(&a.scan(b"oPeNsSh")), vec!["OpenSSH"]);
    }

    #[test]
    fn folding_is_ascii_only_not_unicode() {
        assert_eq!(AhoCorasick::fold_byte(b'A'), b'a');
        assert_eq!(AhoCorasick::fold_byte(b'Z'), b'z');
        assert_eq!(AhoCorasick::fold_byte(b'['), b'[');
        assert_eq!(AhoCorasick::fold_byte(0xC3), 0xC3);
        // A Latin capital A-with-acute is not ASCII 'a', so it must not match.
        let a = ac(&["a"]);
        assert!(a.scan("\u{00C1}".as_bytes()).is_empty());
    }

    #[test]
    fn finds_overlapping_and_suffix_patterns() {
        let a = ac(&["aba", "ba", "bab"]);
        let got = sorted(a.scan(b"ababa"));
        assert_eq!(
            got,
            sorted(vec![
                ("aba".to_string(), 0),
                ("aba".to_string(), 2),
                ("ba".to_string(), 1),
                ("ba".to_string(), 3),
                ("bab".to_string(), 1),
            ])
        );
    }

    #[test]
    fn reports_every_occurrence_not_just_the_first() {
        let a = ac(&["ab"]);
        let hits = a.scan(b"ab-ab-ab");
        assert_eq!(hits.len(), 3);
        // "ab" starts at byte offsets 0, 3 and 6.
        assert_eq!(hits.iter().map(|h| h.1).collect::<Vec<_>>(), vec![0, 3, 6]);
    }

#[test]
fn ignores_empty_and_duplicate_patterns() {
    let mut a = AhoCorasick::new();
    assert!(!a.add(""));
    assert!(!a.add("   "));
    assert!(a.add("alpha"));
    assert!(!a.add("ALPHA"), "duplicate needle must be stored once");
    assert_eq!(a.len(), 1);
}

#[test]
fn a_pattern_keeps_the_spaces_it_was_given() {
    // The C core trims the signature line, never the pattern, so these are three
    // distinct signatures. Trimming them here made this core report ' SSH' at
    // offset 3 where the C core reported it at 2.
    let mut a = AhoCorasick::new();
    assert!(a.add(" SSH"));
    assert!(a.add("SSH"));
    assert!(a.add("SSH "));
    assert_eq!(a.len(), 3, "the three patterns are not the same needle");
    a.build();

    assert_eq!(
        sorted(a.scan(b"xx SSHyy")),
        sorted(vec![(" SSH".to_string(), 2), ("SSH".to_string(), 3)])
    );
}

#[test]
fn a_whitespace_only_pattern_is_still_rejected() {
    // Rejecting a blank pattern and preserving the spaces in a non-blank one
    // are two different rules; fixing the second must not lose the first.
    let mut a = AhoCorasick::new();
    assert!(!a.add(""));
    assert!(!a.add("   "));
    assert!(!a.add("\t\n"));
    assert!(a.add("  x  "));
    assert_eq!(a.len(), 1);
}

    #[test]
    fn empty_automaton_matches_nothing() {
        let a = ac(&[]);
        assert!(a.is_empty());
        assert!(a.scan(b"anything at all").is_empty());
    }

    #[test]
    fn handles_long_shared_prefixes() {
        let a = ac(&[
            "aaaaaaaaaaaaaaaaaaaab",
            "aaaaaaaaaaaaaaaaaaaac",
            "aaaaaaaaaaaaaaaaaaaad",
        ]);
        assert_eq!(labels(&a.scan(b"aaaaaaaaaaaaaaaaaaaac")), vec!["aaaaaaaaaaaaaaaaaaaac"]);
    }

    #[test]
    fn matches_after_a_rebuild_with_new_patterns() {
        let mut a = AhoCorasick::new();
        a.add("alpha");
        a.build();
        assert_eq!(a.scan(b"alpha").len(), 1);
        a.add("beta");
        a.build();
        assert_eq!(labels(&a.scan(b"alpha beta alpha")), vec!["alpha", "beta", "alpha"]);
    }

    #[test]
    fn empty_text_is_safe() {
        let a = ac(&["x"]);
        assert!(a.scan(b"").is_empty());
    }

    #[test]
    fn start_offset_is_zero_for_prefix_match() {
        let a = ac(&["abc"]);
        let hits = a.scan(b"abc");
        assert_eq!(hits[0].1, 0);
    }

    #[test]
    fn pattern_that_is_a_prefix_of_another_still_reports() {
        let a = ac(&["ssh", "ssh-2.0-openssh"]);
        let hits = a.scan(b"ssh-2.0-openssh");
        let mut got = labels(&hits);
        got.sort();
        // "ssh" is a genuine substring at offset 0 and again at offset 12
        // (the tail of "openssh"), so three hits is the correct count.
        assert_eq!(got, vec!["ssh", "ssh", "ssh-2.0-openssh"]);
        let ssh_positions: Vec<usize> = hits
            .iter()
            .filter(|(l, _)| l == "ssh")
            .map(|(_, p)| *p)
            .collect();
        assert_eq!(ssh_positions, vec![0, 12]);
    }
}
