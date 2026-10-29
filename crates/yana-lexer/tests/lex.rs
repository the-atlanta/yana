use yana_lexer::{lex, Token};

#[test]
fn lexes_hello() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/hello.yana")).unwrap();
    let out = lex(&src);
    assert!(out.errors.is_empty(), "lex errors: {:?}", out.errors);
    // comments captured as trivia
    assert!(out.comments.iter().any(|(_, c)| c.contains("hello.yana")));
    // a few spot checks
    let kinds: Vec<_> = out.tokens.iter().map(|t| &t.kind).collect();
    assert!(kinds.iter().any(|k| matches!(k, Token::KwBind)));
    assert!(kinds.iter().any(|k| matches!(k, Token::Ident(s) if s == ".rodata")));
    assert!(kinds.iter().any(|k| matches!(k, Token::HashLBracket)));
    assert!(kinds.iter().any(|k| matches!(k, Token::KwExtern)));
    assert!(kinds.iter().any(|k| matches!(k, Token::Arrow)));
    assert!(kinds.iter().any(|k| matches!(k, Token::Bang)));
}

#[test]
fn lexes_numbers_and_escapes() {
    let out = lex(r#"bind x @ rax: u64 = 0xFF_00; alt x += 1_000; bind s @ .rodata: [u8] = "a\nb\x41";"#);
    assert!(out.errors.is_empty(), "lex errors: {:?}", out.errors);
    let strs: Vec<_> = out.tokens.iter().filter_map(|t| match &t.kind {
        Token::Num(s) => Some(s.as_str()),
        _ => None,
    }).collect();
    assert!(strs.contains(&"0xFF_00") && strs.contains(&"1_000"));
}

#[test]
fn bad_byte_recorded_not_fatal() {
    let out = lex("bind x @ rax: u64 = $;");
    assert_eq!(out.errors.len(), 1);
    // still produced tokens around it
    assert!(out.tokens.iter().any(|t| matches!(t.kind, Token::Semi)));
}

#[test]
fn label_ref_and_pair() {
    let out = lex("branch (n != 0) => 'loop_top; alt rdx:rax = rax as u128;");
    assert!(out.errors.is_empty(), "lex errors: {:?}", out.errors);
    assert!(out.tokens.iter().any(|t| matches!(&t.kind, Token::LabelRef(s) if s == "loop_top")));
    assert!(out.tokens.iter().any(|t| matches!(&t.kind, Token::SlashPercent)) == false);
}
