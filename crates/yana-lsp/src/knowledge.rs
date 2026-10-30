//! One table of YANA knowledge for editor tooling: keywords, registers,
//! types, sections, flags, attributes, and statement snippets. Completion
//! and hover both read from here — the same single-source principle as the
//! instruction table in codegen (§14).

use yana_ast::reg::{GprBase, Reg, RegSize};

/// A completion entry.
pub struct Item {
    pub label: &'static str,
    pub detail: &'static str,
    pub docs: &'static str,
    /// Text to insert (may contain `$1`-style placeholders; LSP snippet).
    pub insert: Option<&'static str>,
}

/// Language keywords with spec references.
pub fn keywords() -> Vec<Item> {
    let mut v = vec![
        Item { label: "bind", detail: "привязка места (§3)", docs: "bind [mut] имя @ место: тип [= значение];", insert: Some("bind ${1:mut }${2:name} @ ${3:rax}: ${4:u64} = ${5:0};") },
        Item { label: "alt", detail: "запись в место (§4.2)", docs: "alt требует mut-привязки; не нужна для bind-инициализации и команд (pop/call/syscall/return).", insert: Some("alt ${1:dst} ${2:=} ${3:src};") },
        Item { label: "push", detail: "в стек, порядок написания (§4.3)", docs: "push { a, b }; — раскрывается в написанном порядке; `_` = пустой слот 8 байт (lea rsp).", insert: Some("push { ${1:rbx} };") },
        Item { label: "pop", detail: "из стека, порядок написания (§4.3)", docs: "pop { b, a }; — порядок не разворачивается.", insert: Some("pop { ${1:rbx} };") },
        Item { label: "branch", detail: "ветвление (§4.4)", docs: "branch (n != 0) => 'label; или branch => 'label; Сырые jmp/jnz не вводятся.", insert: Some("branch (${1:cond}) => '${2:label};") },
        Item { label: "call", detail: "вызов (§5.3)", docs: "call имя { парам: значение }; раскрывается в mov-ы по сигнатуре + call.", insert: Some("call ${1:name} { ${2:args} };") },
        Item { label: "return", detail: "возврат (§5.2)", docs: "return; канонично. return <место>; утверждает где результат (redundant/contract).", insert: Some("return;") },
        Item { label: "syscall", detail: "сырой syscall (§5.5)", docs: "Низкоуровневый выход; номер уже в rax.", insert: Some("syscall;") },
        Item { label: "label", detail: "блок-метка (§6)", docs: "label (имя) { ... } — метка = начало блока, управление проходит насквозь.", insert: Some("label (${1:name}) {\n    $0\n}") },
        Item { label: "fn", detail: "функция (§5.1)", docs: "fn имя([mut] парам @ место: тип, ...) -> результат { ... }", insert: Some("fn ${1:name}(${2:args}) -> ${3:rax: u64} {\n    $0\n}") },
        Item { label: "extern", detail: "внешняя функция (§5.5)", docs: "#[syscall(N)] extern fn write(fd @ rdi: u64, ...) -> rax: i64;", insert: Some("#[syscall(${1:1})]\nextern fn ${2:name}(${3:args}) -> ${4:rax: i64};") },
        Item { label: "const", detail: "константа / const fn (§7, §8)", docs: "const NAME: T = выражение; const fn — вычисление при сборке, без памяти и регистров.", insert: Some("const ${1:NAME}: ${2:u64} = ${3:0};") },
        Item { label: "clobbers", detail: "порча регистров (§5.4)", docs: "clobbers: rcx, r11, — блок есть: портится ровно перечисленное.", insert: Some("clobbers:\n    ${1:rcx},\n    ${2:r11},") },
        Item { label: "mut", detail: "изменяемая привязка (§3)", docs: "По умолчанию привязка неизменяема; запись требует mut + alt.", insert: None },
        Item { label: "as", detail: "приведение (§4.2)", docs: "Расширение по знаковости источника; усечение берёт младшую часть (d as u8 = dl).", insert: None },
        Item { label: "true", detail: "булево (const-выражения)", docs: "", insert: None },
        Item { label: "false", detail: "булево (const-выражения)", docs: "", insert: None },
        Item { label: "if", detail: "if-выражение (§8)", docs: "Только в const-контексте: if cond { a } else { b }", insert: Some("if ${1:cond} { ${2:a} } else { ${3:b} }") },
        Item { label: "else", detail: "ветка if-выражения (§8)", docs: "", insert: None },
        Item { label: "let", detail: "зарезервировано (§1)", docs: "", insert: None },
        Item { label: "macro", detail: "макрос (§9)", docs: "macro имя(a: вид, ...) { тело }; вызов позиционный имя!(a, b) и именованный имя! { a: x, b: y }. Виды фрагментов: place, value, label, type, ident, block. Гигиена: метки и bind внутри макроса получают уникальные имена; раскрытие чистой подстановкой без вычислений.", insert: Some("macro ${1:name}(${2:a}: ${3:place}) {\n    $0\n}") },
        Item { label: "macro_rules", detail: "макрос с правилами (§9)", docs: "macro_rules! имя { (шаблон) => { тело }; ... } с повторениями $(...),* и $(...),+. Фрагменты $x:place, $x:value, ...; рекурсия с лимитом глубины 64.", insert: Some("macro_rules! ${1:name} { ($${2:pattern}) => { ${3:body} }; }") },
    ];
    // `macro`/`macro_rules` are §9 keywords now (not reserved) — the
    // reserved() list below is a separate table.
    v.push(Item { label: "align", detail: "выравнивание стека (§4.3)", docs: "align N; — паддинг до кратности N (lea rsp, флаги не трогаются).", insert: Some("align ${1:16};") });
    v
}

/// Reserved words (§1) — completing them warns they're future syntax.
pub fn reserved() -> &'static [&'static str] {
    &["for", "volatile", "atomic", "preserves", "requires", "ensures", "invariant", "use", "mod", "macro", "macro_rules", "align", "let"]
}

/// All x86-64 register names, grouped.
pub fn registers() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bases = [
        GprBase::A, GprBase::B, GprBase::C, GprBase::D,
        GprBase::Si, GprBase::Di, GprBase::Bp, GprBase::Sp,
        GprBase::R8, GprBase::R9, GprBase::R10, GprBase::R11,
        GprBase::R12, GprBase::R13, GprBase::R14, GprBase::R15,
    ];
    for b in bases {
        for size in [RegSize::R64, RegSize::R32, RegSize::R16, RegSize::R8] {
            let r = Reg::Gpr { base: b, size };
            out.push((r.name().to_string(), format!("{size:?} GPR")));
        }
        if b.has_high8() {
            let r = Reg::GprHigh8(b);
            out.push((r.name().to_string(), "R8 high-byte (legacy)".to_string()));
        }
    }
    out.push(("rip".to_string(), "instruction pointer (memory base only)".to_string()));
    for i in 0..16 {
        out.push((format!("xmm{i}"), "SSE register".to_string()));
    }
    out
}

/// Hover text for a register name.
pub fn register_hover(name: &str) -> Option<String> {
    let reg = Reg::parse(name)?;
    let size = reg.size();
    let family = match reg {
        Reg::Gpr { base, .. } => Some(base),
        Reg::GprHigh8(b) => Some(b),
        _ => None,
    };
    let mut s = format!("**{name}** — x86-64 register, {} bits\n\n", size.bits());
    if let Some(b) = family {
        s.push_str("Aliases: ");
        let mut first = true;
        for sz in [RegSize::R64, RegSize::R32, RegSize::R16, RegSize::R8] {
            let r = Reg::Gpr { base: b, size: sz };
            if !first {
                s.push_str(", ");
            }
            s.push_str(&format!("`{}` ({})", r.name(), sz.bits()));
            first = false;
        }
        s.push('\n');
    }
    Some(s)
}

/// Primitive types (§2).
pub fn types() -> Vec<Item> {
    let mut v = Vec::new();
    for (t, d) in [
        ("u8", "unsigned 8-bit"), ("u16", "unsigned 16-bit"),
        ("u32", "unsigned 32-bit"), ("u64", "unsigned 64-bit"),
        ("usize", "target pointer width (64 on x86-64)"),
        ("i8", "signed 8-bit"), ("i16", "signed 16-bit"),
        ("i32", "signed 32-bit"), ("i64", "signed 64-bit"),
        ("isize", "signed target pointer width"),
        ("u128", "register pair rdx:rax only (§4.5)"),
        ("i128", "signed register pair (§4.5)"),
    ] {
        v.push(Item { label: t, detail: d, docs: "", insert: None });
    }
    v
}

/// Data sections (§7).
pub fn sections() -> Vec<Item> {
    vec![
        Item { label: ".text", detail: "код", docs: "", insert: None },
        Item { label: ".rodata", detail: "данные только для чтения", docs: "", insert: None },
        Item { label: ".data", detail: "инициализируемые данные", docs: "", insert: None },
        Item { label: ".bss", detail: "неинициализируемые данные", docs: "", insert: None },
    ]
}

/// Branch flag names (§4.4).
pub fn flags() -> Vec<Item> {
    vec![
        Item { label: "zero", detail: "ZF — результат нулевой", docs: "branch (zero) => ...; или branch (!zero)", insert: None },
        Item { label: "carry", detail: "CF — перенос", docs: "", insert: None },
        Item { label: "negative", detail: "SF — знак", docs: "", insert: None },
        Item { label: "overflow", detail: "OF — знаковое переполнение", docs: "", insert: None },
        Item { label: "even", detail: "PF — чётность", docs: "", insert: None },
    ]
}

/// Attributes (§1, §5, §7).
pub fn attributes() -> Vec<Item> {
    vec![
        Item { label: "entry", detail: "точка входа (§5.1)", docs: "#[entry] — _start на Linux, _main на macOS; имя функции любое.", insert: Some("#[entry]") },
        Item { label: "syscall", detail: "номер syscall (§5.5)", docs: "#[syscall(1)] extern fn write(...) — раскрывается в mov rax,1; syscall.", insert: Some("#[syscall(${1:1})]") },
        Item { label: "global", detail: "экспорт символа (§5.1)", docs: "Единственный способ экспорта символа (pub убран из языка, SPEC §15).", insert: Some("#[global]") },
        Item { label: "section", detail: "переопределение секции (§7)", docs: r#"#[section(".note")]"#, insert: Some(r#"#[section("${1:.data}")]"#) },
        Item { label: "align", detail: "выравнивание (§7)", docs: "#[align(16)]", insert: Some("#[align(${1:16})]") },
        Item { label: "cfg", detail: "условная компиляция (§13)", docs: r#"#[cfg(arch = "x86-64")], #[cfg(os = "linux")]"#, insert: Some(r#"#[cfg(${1:arch} = "${2:x86-64}")]"#) },
    ]
}

/// Keyword hover docs (spec excerpts).
pub fn keyword_hover(word: &str) -> Option<String> {
    let k = keywords().into_iter().find(|i| i.label == word)?;
    let mut s = format!("**{}** — {}\n", k.label, k.detail);
    if !k.docs.is_empty() {
        s.push_str(&format!("\n{}\n", k.docs));
    }
    Some(s)
}
