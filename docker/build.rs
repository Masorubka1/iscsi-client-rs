use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

fn trimq(s: &str) -> &str {
    s.trim()
        .trim_matches('"')
        .trim_matches('“')
        .trim_matches('”')
}

fn is_nn(s: &str) -> bool {
    let t = trimq(s).trim_end_matches(['h', 'H']);
    matches!(t, "NN" | "nn" | "XX" | "xx")
}

fn parse_hex2(s: &str) -> Option<u16> {
    let t = trimq(s).trim_end_matches(['h', 'H']);
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).ok()
    } else if (t.chars().all(|c| c.is_ascii_hexdigit()) && s.to_ascii_lowercase().ends_with('h'))
        || (t.len() <= 3 && t.chars().all(|c| c.is_ascii_hexdigit()))
    {
        u16::from_str_radix(t, 16).ok()
    } else {
        None
    }
}

/// Try find a `(AAbb-CCdd)`-like range in free text, where tokens end with `h`.
fn find_h_range(desc: &str) -> Option<(u8, u8)> {
    let mut lo = None;
    let mut hi = None;
    // scan for patterns like "80h-FFh" within parentheses or not
    for part in desc.split(['(', ')', ' ']) {
        if let Some((l, r)) = part.split_once('-') {
            let l = l.trim();
            let r = r.trim();
            if l.to_ascii_lowercase().ends_with('h')
                && r.to_ascii_lowercase().ends_with('h')
                && let (Some(a), Some(b)) = (
                    parse_hex2(l).map(|v| v as u8),
                    parse_hex2(r).map(|v| v as u8),
                )
            {
                lo = Some(a);
                hi = Some(b);
                break;
            }
        }
    }
    match (lo, hi) {
        (Some(a), Some(b)) if a <= b => Some((a, b)),
        _ => None,
    }
}

fn replace_nn(desc: &str, val: u8) -> String {
    // Replace both NNh and NN (case-insensitive)
    let mut s = desc
        .replace("NNh", &format!("{:02X}h", val))
        .replace("NNH", &format!("{:02X}h", val))
        .replace("XXh", &format!("{:02X}h", val))
        .replace("XXH", &format!("{:02X}h", val));
    s = s
        .replace("NN", &format!("{:02X}", val))
        .replace("nn", &format!("{:02X}", val))
        .replace("XX", &format!("{:02X}", val))
        .replace("xx", &format!("{:02X}", val));
    s
}

fn parse_line(line: &str, file: &Path, lineno: usize) -> Vec<(u16, u16, String)> {
    let mut out = Vec::new();
    let l = line.split('#').next().unwrap_or("").trim();
    if l.is_empty() {
        return out;
    }

    // Tokenize by any whitespace
    let toks: Vec<&str> = l.split_whitespace().collect();
    if toks.is_empty() {
        return out;
    }

    // Try combined "ASC/ASCQ"
    let (asc_opt, ascq_tok_opt, consumed) = if let Some((a, b)) = trimq(toks[0]).split_once('/') {
        (parse_hex2(a), Some(b), 1usize)
    } else {
        (parse_hex2(toks[0]), toks.get(1).copied(), 2usize)
    };

    let asc = match asc_opt {
        Some(v) => v,
        None => {
            // Strict TSV fallback: ASC\tASCQ\tDESC...
            let parts: Vec<&str> = l.split('\t').filter(|s| !s.trim().is_empty()).collect();
            if parts.len() >= 2
                && let (Some(a), Some(b)) = (parse_hex2(parts[0]), parse_hex2(parts[1]))
            {
                let desc = if parts.len() >= 3 {
                    trimq(&parts[2..].join("\t")).to_string()
                } else {
                    eprintln!("warning: {}:{} has no description", file.display(), lineno);
                    "<unknown>".into()
                };
                out.push((a, b, desc));
                return out;
            }
            panic!("bad ASC '{}' at {}:{}", l, file.display(), lineno);
        }
    };

    let i = consumed;
    let ascq_tok = ascq_tok_opt.unwrap_or("");
    let desc_tokens_start = i;

    // If ASCQ is wildcard (NN/NNh/XX/XXh), expand range from description (or
    // default 00..FF)
    if is_nn(ascq_tok) {
        // Description = everything after consumed tokens
        if desc_tokens_start >= toks.len() {
            eprintln!("warning: {}:{} has no description", file.display(), lineno);
            return out;
        }
        let mut desc = toks[desc_tokens_start..].join(" ");
        desc = trimq(&desc).to_string();

        let (lo, hi) = find_h_range(&desc).unwrap_or((0x00, 0xFF));

        for v in lo..=hi {
            let d = replace_nn(&desc, v);
            out.push((asc, v as u16, d));
        }
        return out;
    }

    // Concrete ASCQ path
    let ascq = match parse_hex2(ascq_tok) {
        Some(v) => v,
        None => {
            // Maybe strict TSV fallback if 2nd token wasn't the ASCQ
            let parts: Vec<&str> = l.split('\t').filter(|s| !s.trim().is_empty()).collect();
            if parts.len() >= 2
                && let Some(b) = parse_hex2(parts[1])
            {
                let a = asc;
                let desc = if parts.len() >= 3 {
                    trimq(&parts[2..].join("\t")).to_string()
                } else {
                    eprintln!("warning: {}:{} has no description", file.display(), lineno);
                    "<unknown>".into()
                };
                out.push((a, b, desc));
                return out;
            }
            panic!("bad ASC/ASCQ '{}' at {}:{}", l, file.display(), lineno);
        }
    };

    // Description = everything after the two tokens
    if desc_tokens_start >= toks.len() {
        eprintln!("warning: {}:{} has no description", file.display(), lineno);
        out.push((asc, ascq, "<unknown>".into()));
        return out;
    }
    let desc = trimq(&toks[desc_tokens_start..].join(" ")).to_string();
    out.push((asc, ascq, desc));
    out
}

fn main() {
    let tsv_rel = "asc_ascq.tsv";
    let manifest_dir = PathBuf::from("docs");
    let input = manifest_dir.join(tsv_rel);

    println!("cargo:rerun-if-changed={}", input.display());

    let file = fs::File::open(&input)
        .unwrap_or_else(|e| panic!("failed to open {}: {e}", input.display()));
    let rdr = BufReader::new(file);

    let mut entries: Vec<(u16, u16, String)> = Vec::new();

    for (lineno, line) in rdr.lines().enumerate() {
        let line = line.expect("read line");
        let mut parsed = parse_line(&line, &input, lineno + 1);
        entries.append(&mut parsed);
    }

    // Sort by combined 16-bit code (ASC<<8|ASCQ)
    entries.sort_by_key(|(asc, ascq, _)| (*asc << 8) | *ascq);

    // Generate Rust source
    let out_dir = PathBuf::from("src/models/data");
    let out_rs = out_dir.join("asc_ascq_gen.rs");

    let mut rs = String::new();
    rs.push_str("// @generated by build.rs — DO NOT EDIT\n");
    rs.push_str("use super::Entry;\n");
    rs.push_str("pub(crate) const ASC_ASCQ: &[Entry] = &[\n");
    for (asc, ascq, desc) in entries {
        let safe = desc.replace('\\', "\\\\").replace('"', "\\\"");
        rs.push_str(&format!(
            "    Entry {{ code: 0x{:04X}, desc: \"{}\" }},\n",
            (asc << 8) | ascq,
            safe
        ));
    }
    rs.push_str("];\n");

    fs::write(&out_rs, rs).expect("write asc_ascq_gen.rs failed");
}
