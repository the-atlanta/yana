//! Token definitions (logos) + unescape helpers.
//!
//! Comments are trivia (§1): the lexer callback stashes them in a thread-local
//! sink so the NASM backend can echo them (§13); they never reach the grammar.

use logos::Logos;

#[derive(Logos, Debug, Clone, PartialEq, Eq)]
#[logos(skip r"[ \t\r\n\f]+")]
pub enum Token {
    // ---- trivia ----
    #[regex(r"//[^\n]*", comment_callback, allow_greedy = true)]
    Comment,

    // ---- literals ----
    /// `0x1F`, `0b1010`, `1_000_000`, `255`
    #[regex(r"0[xX][0-9a-fA-F][0-9a-fA-F_]*", str_payload)]
    #[regex(r"0[bB][01][01_]*", str_payload)]
    #[regex(r"[0-9][0-9_]*", str_payload)]
    Num(String),

    /// `'a'`, `'\n'`, `'\x41'`
    #[regex(r#"'([^'\\\n]|\\(n|r|t|0|\\|'|"|x[0-9a-fA-F]{2}))'"#, char_callback)]
    Char(u8),

    /// `"..."` — raw source text including quotes; unescaped in the parser.
    #[regex(r#""([^"\\\n]|\\.)*""#, str_payload)]
    Str(String),

    /// identifier / register name / section name (`.rodata` — leading dot).
    /// `_` is a valid ident and the parser treats it as the discard place (§3).
    #[regex(r"[A-Za-z_][A-Za-z0-9_]*", str_payload)]
    // longest-match wins, so `.rodata` beats the `.` token; the parser
    // validates section names anyway
    #[regex(r"\.(text|rodata|data|bss)", str_payload)]
    Ident(String),

    // ---- keywords ----
    #[token("bind")] KwBind,
    #[token("mut")] KwMut,
    #[token("alt")] KwAlt,
    #[token("push")] KwPush,
    #[token("pop")] KwPop,
    #[token("branch")] KwBranch,
    #[token("call")] KwCall,
    #[token("return")] KwReturn,
    #[token("syscall")] KwSyscall,
    #[token("label")] KwLabel,
    #[token("fn")] KwFn,
    #[token("extern")] KwExtern,
    #[token("pub")] KwPub,
    #[token("const")] KwConst,
    #[token("clobbers")] KwClobbers,
    #[token("as")] KwAs,
    #[token("align")] KwAlign,
    #[token("atomic")] KwAtomic,
    #[token("volatile")] KwVolatile,
    #[token("true")] KwTrue,
    #[token("false")] KwFalse,
    #[token("if")] KwIf,
    #[token("else")] KwElse,
    #[token("let")] KwLet,

    // reserved for the future (§1) — tokenized so we can give a clear
    // "reserved keyword" diagnostic instead of a generic parse error.
    #[token("for")] KwFor,
    #[token("preserves")] KwPreserves,
    #[token("requires")] KwRequires,
    #[token("ensures")] KwEnsures,
    #[token("invariant")] KwInvariant,
    #[token("use")] KwUse,
    #[token("mod")] KwMod,
    #[token("macro")] KwMacro,
    #[token("macro_rules")] KwMacroRules,

    // ---- types (§2) ----
    #[token("u8")] Tu8,
    #[token("u16")] Tu16,
    #[token("u32")] Tu32,
    #[token("u64")] Tu64,
    #[token("u128")] Tu128,
    #[token("usize")] Tusize,
    #[token("i8")] Ti8,
    #[token("i16")] Ti16,
    #[token("i32")] Ti32,
    #[token("i64")] Ti64,
    #[token("i128")] Ti128,
    #[token("isize")] Tisize,

    // ---- flag names (§4.4) ----
    #[token("zero")] FlagZero,
    #[token("carry")] FlagCarry,
    #[token("negative")] FlagNegative,
    #[token("overflow")] FlagOverflow,
    #[token("even")] FlagEven,

    // ---- punctuation (longest match wins in logos) ----
    #[token("<<=")] ShlEq,
    #[token(">>=")] ShrEq,
    #[token("/%")] SlashPercent,
    #[token("::")] ColonColon,
    #[token("->")] Arrow,
    #[token("=>")] FatArrow,
    #[token("+=")] PlusEq,
    #[token("-=")] MinusEq,
    #[token("*=")] StarEq,
    #[token("^=")] CaretEq,
    #[token("&=")] AmpEq,
    #[token("|=")] PipeEq,
    #[token("==")] EqEq,
    #[token("!=")] Ne,
    #[token("<=")] Le,
    #[token(">=")] Ge,
    #[token("&&")] AmpAmp,
    #[token("||")] PipePipe,
    #[token("<<")] Shl,
    #[token(">>")] Shr,
    #[token("..")] DotDot,
    #[token("#[")] HashLBracket,
    #[token(";")] Semi,
    #[token(",")] Comma,
    #[token(":")] Colon,
    #[token("@")] At,
    #[token("&")] Amp,
    #[token("=")] Eq,
    #[token("<")] Lt,
    #[token(">")] Gt,
    #[token("!")] Bang,
    #[token("+")] Plus,
    #[token("-")] Minus,
    #[token("*")] Star,
    #[token("/")] Slash,
    #[token("%")] Percent,
    #[token("^")] Caret,
    #[token("|")] Pipe,
    #[token(".")] Dot,
    #[token("(")] LParen,
    #[token(")")] RParen,
    #[token("{")] LBrace,
    #[token("}")] RBrace,
    #[token("[")] LBracket,
    #[token("]")] RBracket,
    #[token("#")] Hash,

    /// `'label` reference (§1) — quote + identifier, no closing quote.
    #[regex(r"'[A-Za-z_][A-Za-z0-9_]*", label_callback)]
    LabelRef(String),

    // ---- synthetic variants, never produced by logos ----
    // The grammar's fallible actions (int parse, string unescape, register
    // check) fail with these so LALRPOP's ParseError::User carries a span.
    // The driver turns them into precise diagnostics.

    /// An integer literal that doesn't fit i128 / has invalid digits.
    BadNum(BadLit),
    /// A string literal with an invalid escape sequence.
    BadEscape(BadLit),
    /// An identifier that must be a register but isn't (e.g. `foo:rax` pair).
    BadReg(BadLit),

    /// Synthetic register pair `rdx:rax` (§4.5), collapsed by the lexer
    /// pre-pass (§0.5 slot). Register names and type keywords are disjoint
    /// token classes, so `Ident ":" Ident(reg)` is unambiguously a pair —
    /// collapsing it removes a 2-token ambiguity the LALR(1) parser can't split.
    PairReg((yana_ast::reg::Reg, yana_ast::reg::Reg, u32, u32)),
    /// Synthetic: `pub` was removed from the language (SPEC §15, 29.10) —
    /// the grammar fails with this token so the driver can emit a precise
    /// "use #[global]" diagnostic instead of a generic parse error.
    RemovedPub(BadLit),
}

/// Payload for synthetic error tokens (logos requires a single field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadLit {
    /// The offending source text.
    pub text: String,
    /// Byte span in the source.
    pub lo: u32,
    pub hi: u32,
}

impl BadLit {
    pub fn new(text: impl Into<String>, lo: u32, hi: u32) -> Self {
        BadLit { text: text.into(), lo, hi }
    }

    pub fn span(&self) -> yana_ast::Span {
        yana_ast::Span::new(self.lo, self.hi)
    }
}

// ---------------------------------------------------------------------------
// Display — required by LALRPOP for error messages
// ---------------------------------------------------------------------------

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Comment => write!(f, "comment"),
            Token::Num(s) => write!(f, "{s}"),
            Token::Char(c) => write!(f, "'{}'", *c as char),
            Token::Str(s) => write!(f, "{s}"),
            Token::Ident(s) => write!(f, "{s}"),
            Token::LabelRef(s) => write!(f, "'{s}"),
            Token::BadNum(b) => write!(f, "{}", b.text),
            Token::BadEscape(b) => write!(f, "{}", b.text),
            Token::BadReg(b) => write!(f, "{}", b.text),
            Token::RemovedPub(_) => write!(f, "pub"),
            Token::PairReg((hi, lo, ..)) => write!(f, "{}:{}", hi.name(), lo.name()),
            other => write!(f, "{other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// logos callbacks
// ---------------------------------------------------------------------------

fn str_payload(lex: &mut logos::Lexer<'_, Token>) -> String {
    lex.slice().to_string()
}

fn label_callback(lex: &mut logos::Lexer<'_, Token>) -> String {
    lex.slice()[1..].to_string()
}

fn char_callback(lex: &mut logos::Lexer<'_, Token>) -> Option<u8> {
    let s = lex.slice();
    let inner = &s[1..s.len() - 1];
    Some(unescape_char(inner))
}

// ---------------------------------------------------------------------------
// comment trivia side channel
// ---------------------------------------------------------------------------

thread_local! {
    static COMMENT_SINK: std::cell::RefCell<Option<Vec<(u32, String)>>> =
        const { std::cell::RefCell::new(None) };
}

/// Start capturing comments. Call before lexing.
pub fn begin_comment_capture() {
    COMMENT_SINK.with(|s| *s.borrow_mut() = Some(Vec::new()));
}

/// Take captured comments as `(byte_offset, text_without_slashes)`.
pub fn take_comments() -> Vec<(u32, String)> {
    COMMENT_SINK.with(|s| s.borrow_mut().take().unwrap_or_default())
}

fn comment_callback(lex: &mut logos::Lexer<'_, Token>) -> Token {
    let text = lex.slice();
    let stripped = text.strip_prefix("//").unwrap_or(text).to_string();
    let off = lex.span().start as u32;
    COMMENT_SINK.with(|s| {
        if let Some(v) = s.borrow_mut().as_mut() {
            v.push((off, stripped));
        }
    });
    Token::Comment
}

// ---------------------------------------------------------------------------
// unescaping (§1)
// ---------------------------------------------------------------------------

/// Unescape a char literal body (without quotes). The regex guarantees validity.
pub fn unescape_char(inner: &str) -> u8 {
    let mut it = inner.chars();
    let c = it.next().unwrap();
    if c != '\\' {
        return c as u8;
    }
    match it.next().unwrap() {
        'n' => b'\n',
        'r' => b'\r',
        't' => b'\t',
        '0' => b'\0',
        '\\' => b'\\',
        '\'' => b'\'',
        '"' => b'"',
        'x' => u8::from_str_radix(&inner[2..], 16).unwrap(),
        _ => unreachable!(),
    }
}

/// Unescape a string literal body (without the outer quotes) into bytes.
/// Returns `Err((byte_offset_within_body, bad_escape))` for invalid escapes.
pub fn unescape_string(body: &str) -> Result<Vec<u8>, (usize, String)> {
    let mut out = Vec::new();
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    let mut byte_off = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            byte_off += c.len_utf8();
            i += 1;
            continue;
        }
        i += 1;
        byte_off += 1;
        if i >= chars.len() {
            return Err((byte_off, "\\".to_string()));
        }
        let e = chars[i];
        byte_off += e.len_utf8();
        match e {
            'n' => out.push(b'\n'),
            'r' => out.push(b'\r'),
            't' => out.push(b'\t'),
            '0' => out.push(b'\0'),
            '\\' => out.push(b'\\'),
            '\'' => out.push(b'\''),
            '"' => out.push(b'"'),
            'x' => {
                if i + 2 >= chars.len() {
                    return Err((byte_off, "\\x".to_string()));
                }
                let hex: String = chars[i + 1..i + 3].iter().collect();
                match u8::from_str_radix(&hex, 16) {
                    Ok(v) => out.push(v),
                    Err(_) => return Err((byte_off, format!("\\x{hex}"))),
                }
                i += 2;
                byte_off += 2;
            }
            _ => return Err((byte_off, format!("\\{e}"))),
        }
        i += 1;
    }
    Ok(out)
}
