use std::ops::Range;

/// Prefixes that identify a credential type. Kept in views so tools that
/// validate the shape of a token still accept it. Longest match wins.
const KNOWN_PREFIXES: &[&str] = &[
    "sk-ant-api03-",
    "github_pat_",
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "pk_test_",
    "rk_live_",
    "rk_test_",
    "sk-proj-",
    "dop_v1_",
    "whsec_",
    "shpat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xapp-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "npm_",
    "AKIA",
    "ASIA",
    "AIza",
    "sk-",
    "SG.",
    "hf_",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    pub key: Option<String>,
    pub span: Range<usize>,
}

/// Find every byte range a view must replace. Spans cover value bytes: no
/// key, no quotes, no trailing whitespace, never a line terminator.
///
/// Dotenv has no single grammar, so this fails closed wherever dialects
/// disagree. Comment bodies are masked (people comment out old keys). An
/// unquoted value runs to end of line, since docker env files have no inline
/// comments. A lone CR ends a line, since some parsers treat it that way.
/// Lines that are not KEY=VALUE are masked whole.
pub fn dotenv_values(src: &[u8]) -> Vec<Value> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < src.len() {
        let line_end = find_line_end(src, i);
        let line = &src[i..line_end];
        let lead = line.iter().take_while(|b| is_blank(**b)).count();
        let body = &line[lead..];
        if body.is_empty() {
            i = next_line(src, line_end);
            continue;
        }
        if body[0] == b'#' {
            push_opaque(src, &mut out, i + lead + 1, line_end);
            i = next_line(src, line_end);
            continue;
        }
        match parse_assignment(src, i + lead, line_end) {
            Some((key, vstart)) => {
                i = push_value(src, &mut out, Some(key), vstart, line_end);
            }
            None => {
                push_opaque(src, &mut out, i + lead, line_end);
                i = next_line(src, line_end);
            }
        }
    }
    out
}

fn find_line_end(src: &[u8], from: usize) -> usize {
    src[from..]
        .iter()
        .position(|b| *b == b'\n' || *b == b'\r')
        .map_or(src.len(), |n| from + n)
}

fn next_line(src: &[u8], line_end: usize) -> usize {
    if src.get(line_end) == Some(&b'\r') && src.get(line_end + 1) == Some(&b'\n') {
        line_end + 2
    } else {
        line_end + 1
    }
}

fn push_opaque(src: &[u8], out: &mut Vec<Value>, mut start: usize, end: usize) {
    while start < end && is_blank(src[start]) {
        start += 1;
    }
    let end = trim_end(src, start, end);
    if start < end {
        out.push(Value {
            key: None,
            span: start..end,
        });
    }
}

/// Returns the key and the offset where the value starts.
fn parse_assignment(src: &[u8], start: usize, line_end: usize) -> Option<(String, usize)> {
    let mut p = start;
    if src[p..line_end].starts_with(b"export") {
        let after = p + 6;
        if after < line_end && is_blank(src[after]) {
            p = after;
            while p < line_end && is_blank(src[p]) {
                p += 1;
            }
        }
    }
    let kstart = p;
    if p >= line_end || !(src[p].is_ascii_alphabetic() || src[p] == b'_') {
        return None;
    }
    while p < line_end && (src[p].is_ascii_alphanumeric() || matches!(src[p], b'_' | b'.' | b'-')) {
        p += 1;
    }
    let key = String::from_utf8_lossy(&src[kstart..p]).into_owned();
    while p < line_end && is_blank(src[p]) {
        p += 1;
    }
    if p >= line_end || src[p] != b'=' {
        return None;
    }
    p += 1;
    while p < line_end && is_blank(src[p]) {
        p += 1;
    }
    Some((key, p))
}

/// Push the value starting at `vstart` and return the offset of the next line.
fn push_value(
    src: &[u8],
    out: &mut Vec<Value>,
    key: Option<String>,
    vstart: usize,
    line_end: usize,
) -> usize {
    if vstart >= line_end {
        return next_line(src, line_end);
    }
    let q = src[vstart];
    if matches!(q, b'"' | b'\'' | b'`') {
        // Quoted values may span lines. Find the closing quote; double quotes
        // honour backslash escapes.
        let mut p = vstart + 1;
        let mut close = None;
        while p < src.len() {
            if q == b'"' && src[p] == b'\\' {
                p += 2;
                continue;
            }
            if src[p] == q {
                close = Some(p);
                break;
            }
            p += 1;
        }
        match close {
            Some(c) => {
                split_on_newlines(out, &key, src, vstart + 1, c);
                // Whatever follows the closing quote, comment or not, is masked.
                let end = find_line_end(src, c);
                push_opaque(src, out, c + 1, end);
                next_line(src, end)
            }
            None => {
                // Unterminated quote: mask the rest of the file.
                split_on_newlines(out, &key, src, vstart + 1, src.len());
                src.len()
            }
        }
    } else {
        let end = trim_end(src, vstart, line_end);
        if end > vstart {
            out.push(Value {
                key,
                span: vstart..end,
            });
        }
        next_line(src, line_end)
    }
}

fn split_on_newlines(
    out: &mut Vec<Value>,
    key: &Option<String>,
    src: &[u8],
    start: usize,
    end: usize,
) {
    let mut s = start;
    for p in start..end {
        if src[p] == b'\n' || src[p] == b'\r' {
            if p > s {
                out.push(Value {
                    key: key.clone(),
                    span: s..p,
                });
            }
            s = p + 1;
        }
    }
    if end > s {
        out.push(Value {
            key: key.clone(),
            span: s..end,
        });
    }
}

fn trim_end(src: &[u8], start: usize, mut end: usize) -> usize {
    while end > start && (is_blank(src[end - 1]) || src[end - 1] == b'\r') {
        end -= 1;
    }
    end
}

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn prefix_len(value: &[u8]) -> usize {
    KNOWN_PREFIXES
        .iter()
        .filter(|p| value.starts_with(p.as_bytes()) && value.len() > p.len())
        .map(|p| p.len())
        .max()
        .unwrap_or(0)
}

/// Redacted view: known prefix kept, every other value byte replaced. All-digit
/// values become zeros so numeric parsers still accept them. Byte length of
/// the file is unchanged.
pub fn redact(src: &[u8]) -> Vec<u8> {
    let mut out = src.to_vec();
    for v in dotenv_values(src) {
        let bytes = &src[v.span.clone()];
        let keep = prefix_len(bytes);
        let rest = &bytes[keep..];
        let fill = if rest.iter().all(u8::is_ascii_digit) {
            b'0'
        } else {
            b'x'
        };
        for b in &mut out[v.span.start + keep..v.span.end] {
            *b = fill;
        }
    }
    out
}

/// Canary view: same layout as the real file with random values that look
/// like the real ones. The alphabet is chosen from what the real value uses
/// so an AKIA key still looks like an AKIA key.
pub fn canary(src: &[u8]) -> Vec<u8> {
    let mut out = src.to_vec();
    for v in dotenv_values(src) {
        let bytes = &src[v.span.clone()];
        let keep = prefix_len(bytes);
        let rest = &bytes[keep..];
        let alphabet = alphabet_for(rest);
        let mut rnd = vec![0u8; rest.len()];
        getrandom::fill(&mut rnd).expect("getrandom failed");
        for (i, b) in out[v.span.start + keep..v.span.end].iter_mut().enumerate() {
            *b = alphabet[rnd[i] as usize % alphabet.len()];
        }
    }
    out
}

fn alphabet_for(rest: &[u8]) -> &'static [u8] {
    const DIGITS: &[u8] = b"0123456789";
    const HEX: &[u8] = b"0123456789abcdef";
    const UPPER_ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const BASE62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    if rest.iter().all(u8::is_ascii_digit) {
        DIGITS
    } else if rest.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)) {
        HEX
    } else if rest
        .iter()
        .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
    {
        UPPER_ALNUM
    } else {
        BASE62
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# stripe
STRIPE_KEY=sk_test_FAKEFAKEFAKE00
export GITHUB_TOKEN=ghp_FAKEtoken0000000
AWS_ACCESS_KEY_ID = AKIAFAKEFAKEFAKE0000
PORT=5432
EMPTY=
QUOTED=\"pa ss#word\" # trailing comment
SINGLE='it''s'
INLINE=abc # comment here
MULTI=\"line one
line two\"
garbage line with no equals
DB_URL=postgres://u:p@h:5432/db\r
";

    fn val<'a>(src: &'a [u8], key: &str) -> Vec<&'a str> {
        dotenv_values(src)
            .into_iter()
            .filter(|v| v.key.as_deref() == Some(key))
            .map(|v| std::str::from_utf8(&src[v.span]).unwrap())
            .collect()
    }

    #[test]
    fn parses_values() {
        let s = SAMPLE.as_bytes();
        assert_eq!(val(s, "STRIPE_KEY"), ["sk_test_FAKEFAKEFAKE00"]);
        assert_eq!(val(s, "GITHUB_TOKEN"), ["ghp_FAKEtoken0000000"]);
        assert_eq!(val(s, "AWS_ACCESS_KEY_ID"), ["AKIAFAKEFAKEFAKE0000"]);
        assert_eq!(val(s, "PORT"), ["5432"]);
        assert!(val(s, "EMPTY").is_empty());
        assert_eq!(val(s, "QUOTED"), ["pa ss#word"]);
        assert_eq!(val(s, "INLINE"), ["abc # comment here"]);
        assert_eq!(val(s, "MULTI"), ["line one", "line two"]);
        assert_eq!(val(s, "DB_URL"), ["postgres://u:p@h:5432/db"]);
        let opaque: Vec<_> = dotenv_values(s)
            .into_iter()
            .filter(|v| v.key.is_none())
            .map(|v| std::str::from_utf8(&s[v.span]).unwrap().to_string())
            .collect();
        assert_eq!(
            opaque,
            [
                "stripe",
                "# trailing comment",
                "'s'",
                "garbage line with no equals"
            ]
        );
    }

    #[test]
    fn redaction_keeps_layout() {
        let s = SAMPLE.as_bytes();
        let r = redact(s);
        assert_eq!(r.len(), s.len());
        let r = String::from_utf8(r).unwrap();
        assert!(r.contains("STRIPE_KEY=sk_test_xxxxxxxxxxxxxx\n"));
        assert!(r.contains("export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxx\n"));
        assert!(r.contains("AWS_ACCESS_KEY_ID = AKIAxxxxxxxxxxxxxxxx\n"));
        assert!(r.contains("PORT=0000\n"));
        assert!(r.contains("QUOTED=\"xxxxxxxxxx\" xxxxxxxxxxxxxxxxxx\n"));
        assert!(r.contains("INLINE=xxxxxxxxxxxxxxxxxx\n"));
        assert!(r.contains("MULTI=\"xxxxxxxx\nxxxxxxxx\"\n"));
        assert!(r.starts_with("# xxxxxx\n"));
        assert!(r.contains("SINGLE='xx'xxx\n"));
        assert!(!r.contains("garbage"));
        assert!(r.contains("DB_URL=xxxxxxxxxxxxxxxxxxxxxxxx\r\n"));
    }

    #[test]
    fn canary_keeps_layout_and_changes_values() {
        let s = SAMPLE.as_bytes();
        let c = canary(s);
        assert_eq!(c.len(), s.len());
        let c = String::from_utf8(c).unwrap();
        assert!(!c.contains("51HxQabcDEF123"));
        let line = c.lines().find(|l| l.starts_with("AWS_ACCESS_KEY_ID")).unwrap();
        let v = line.rsplit(' ').next().unwrap();
        assert!(v.starts_with("AKIA"));
        assert!(v[4..].bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()));
        let port = c.lines().find(|l| l.starts_with("PORT=")).unwrap();
        assert!(port[5..].bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn non_utf8_and_unterminated_quote() {
        let s = b"A=\xff\xfe\nB=\"never closed\nC=still inside\n".to_vec();
        let r = redact(&s);
        assert_eq!(r.len(), s.len());
        assert_eq!(&r[..5], b"A=xx\n");
        assert!(!r.windows(5).any(|w| w == b"still"));
    }

    #[test]
    fn lone_cr_ends_a_line() {
        let s = b"# note\rSECRET=hunter2\r\nB=1\rC=2";
        let r = redact(s);
        assert_eq!(r.len(), s.len());
        assert_eq!(&r[..], b"# xxxx\rSECRET=xxxxxxx\r\nB=0\rC=0");
    }

    #[test]
    fn commented_out_keys_are_masked() {
        let r = redact(b"#OLD=sk_test_abcdef\n  # KEY=ghp_123\n");
        assert_eq!(&r[..], b"#xxxxxxxxxxxxxxxxxx\n  # xxxxxxxxxxx\n");
    }

    #[test]
    fn prefix_alone_is_not_kept() {
        // A value that is exactly a prefix keeps nothing, or it would be served verbatim.
        let r = redact(b"K=sk-\n");
        assert_eq!(r, b"K=xxx\n");
    }
}
