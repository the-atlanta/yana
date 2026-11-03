//! Minimal Mach-O 64-bit object writer for the x86-64 backend (F8).
//!
//! This emits an `MH_OBJECT` file with the same four sections the ELF writer
//! uses (`__text`, `__const`, `__data`, `__bss`) plus a symbol table and
//! x86-64 relocations. It is deliberately small: `ld64`/`clang` can link the
//! result on macOS, but no macOS-specific executable layout is produced here
//! (that needs a Mach-O `MH_EXECUTE` writer and the libSystem entry shim).
//!
//! Relocation mapping:
//! - [`RelocKind::Pc32`] → `X86_64_RELOC_SIGNED` (pcrel, 4 bytes);
//! - [`RelocKind::Plt32`] → `X86_64_RELOC_BRANCH` (pcrel, 4 bytes);
//! - [`RelocKind::Abs32`] → `X86_64_RELOC_UNSIGNED` (4 bytes);
//! - [`RelocKind::Abs64`] → `X86_64_RELOC_UNSIGNED` (8 bytes).
//!
//! Mach-O has no explicit addend: the addend lives in the section bytes, so
//! the writer patches `enc.text` at every relocation site before emitting it.

use std::collections::HashMap;

use yana_ast::place::SectionKind;
use yana_codegen::{Module, SymbolKind};

use crate::encode::{AsmError, EncodedText, RelocKind};
use crate::elf::{align, bss_size_of, section_bytes_of};

const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
const MH_OBJECT: u32 = 1;

const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;

const S_ZEROFILL: u32 = 0x1;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

const N_EXT: u8 = 0x01;
const N_UNDF: u8 = 0x00;
const N_SECT: u8 = 0x0e;

const X86_64_RELOC_UNSIGNED: u32 = 0;
const X86_64_RELOC_SIGNED: u32 = 1;
const X86_64_RELOC_BRANCH: u32 = 2;

/// Write an `MH_OBJECT` Mach-O file from the encoded x86-64 text.
pub fn write_object(module: &Module, enc: &EncodedText) -> Result<Vec<u8>, AsmError> {
    let (rodata, _) = section_bytes_of(module, SectionKind::RoData);
    let (data, _) = section_bytes_of(module, SectionKind::Data);
    let bss = bss_size_of(module);

    // Mach-O addends are stored in the section content.
    let mut text = enc.text.clone();
    for p in &enc.patches {
        let at = p.at;
        match p.width {
            4 if at + 4 <= text.len() => {
                text[at..at + 4].copy_from_slice(&(p.addend as i32).to_le_bytes());
            }
            8 if at + 8 <= text.len() => {
                text[at..at + 8].copy_from_slice(&(p.addend as i64).to_le_bytes());
            }
            _ => {
                return Err(AsmError::Layout(format!(
                    "relocation at {} with width {} is out of bounds",
                    p.at, p.width
                )))
            }
        }
    }

    // Section virtual addresses inside the object (start at 0, like clang).
    let text_addr = 0u64;
    let const_addr = align(text.len(), 8) as u64;
    let data_addr = align((const_addr as usize) + rodata.len(), 8) as u64;
    let bss_addr = align((data_addr as usize) + data.len(), 8) as u64;
    let vmsize = bss_addr + bss;

    // Symbol table: locals, then external definitions, then undefineds.
    // Mach-O requires that order for LC_DYSYMTAB.
    let mut strtab: Vec<u8> = vec![0];
    let mut syms: Vec<u8> = Vec::new();
    let mut index_of: HashMap<usize, u32> = HashMap::new();
    let mut n_local = 0u32;
    let mut n_global = 0u32;
    let mut n_undef = 0u32;

    let mut push_sym = |syms: &mut Vec<u8>,
                        strtab: &mut Vec<u8>,
                        name: &str,
                        n_type: u8,
                        n_sect: u8,
                        n_value: u64|
     -> u32 {
        let idx = (syms.len() / 16) as u32;
        let n_strx = strtab.len() as u32;
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
        syms.extend_from_slice(&n_strx.to_le_bytes());
        syms.push(n_type);
        syms.push(n_sect);
        syms.extend_from_slice(&0u16.to_le_bytes()); // n_desc
        syms.extend_from_slice(&n_value.to_le_bytes());
        idx
    };

    // 1. Local definitions.
    for (i, s) in module.symbols.iter().enumerate() {
        if s.exported || matches!(s.kind, SymbolKind::Const { .. } | SymbolKind::ExternFn | SymbolKind::ExternStatic { .. }) {
            continue;
        }
        let (sect, value) = match &s.kind {
            SymbolKind::Function { .. } => (1u8, text_addr + enc.fn_offsets.get(&i).copied().unwrap_or(0)),
            SymbolKind::Static { section, offset, .. } => {
                let (sect, addr) = static_section(*section, text_addr, const_addr, data_addr, bss_addr);
                (sect, addr + *offset)
            }
            _ => continue,
        };
        index_of.insert(i, push_sym(&mut syms, &mut strtab, &s.name, N_SECT, sect, value));
        n_local += 1;
    }

    // 2. External definitions.
    for (i, s) in module.symbols.iter().enumerate() {
        if !s.exported || matches!(s.kind, SymbolKind::Const { .. } | SymbolKind::ExternFn | SymbolKind::ExternStatic { .. }) {
            continue;
        }
        let (sect, value) = match &s.kind {
            SymbolKind::Function { .. } => (1u8, text_addr + enc.fn_offsets.get(&i).copied().unwrap_or(0)),
            SymbolKind::Static { section, offset, .. } => {
                let (sect, addr) = static_section(*section, text_addr, const_addr, data_addr, bss_addr);
                (sect, addr + *offset)
            }
            _ => continue,
        };
        index_of.insert(
            i,
            push_sym(&mut syms, &mut strtab, &s.name, N_SECT | N_EXT, sect, value),
        );
        n_global += 1;
    }

    // 3. Undefined symbols (real extern calls and imported statics).
    for (i, s) in module.symbols.iter().enumerate() {
        let undef = match &s.kind {
            SymbolKind::ExternFn => s.syscall.is_none(),
            SymbolKind::ExternStatic { .. } => true,
            _ => false,
        };
        if !undef {
            continue;
        }
        index_of.insert(
            i,
            push_sym(&mut syms, &mut strtab, &s.name, N_UNDF | N_EXT, 0, 0),
        );
        n_undef += 1;
    }

    // Relocations for __text.
    let mut relocs: Vec<u8> = Vec::new();
    for p in &enc.patches {
        let sym = *index_of.get(&p.sym).ok_or_else(|| {
            AsmError::Layout(format!("relocation references unknown symbol #{}", p.sym))
        })?;
        let (rtype, pcrel, length) = match p.kind {
            RelocKind::Pc32 => (X86_64_RELOC_SIGNED, 1u32, 2u32),
            RelocKind::Plt32 => (X86_64_RELOC_BRANCH, 1, 2),
            RelocKind::Abs32 => (X86_64_RELOC_UNSIGNED, 0, 2),
            RelocKind::Abs64 => (X86_64_RELOC_UNSIGNED, 0, 3),
        };
        relocs.extend_from_slice(&(p.at as i32).to_le_bytes());
        let info = (sym & 0x00ff_ffff)
            | (pcrel << 24)
            | (length << 25)
            | (1 << 27) // r_extern
            | (rtype << 28);
        relocs.extend_from_slice(&info.to_le_bytes());
    }

    // File layout.
    let nsects = 4u32;
    let seg_cmd_size = 72 + nsects * 80;
    let sizeofcmds = seg_cmd_size + 24 + 80;
    let cmds_end = 32 + sizeofcmds as usize;
    let text_off = align(cmds_end, 16);
    let const_off = align(text_off + text.len(), 8);
    let data_off = align(const_off + rodata.len(), 8);
    let reloc_off = align(data_off + data.len(), 4);
    let symoff = align(reloc_off + relocs.len(), 8);
    let stroff = symoff + syms.len();
    let end = stroff + strtab.len();

    let mut out: Vec<u8> = Vec::with_capacity(end);

    // mach_header_64
    out.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    out.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
    out.extend_from_slice(&CPU_SUBTYPE_X86_64_ALL.to_le_bytes());
    out.extend_from_slice(&MH_OBJECT.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes()); // ncmds: segment, symtab, dysymtab
    out.extend_from_slice(&sizeofcmds.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved

    // LC_SEGMENT_64
    out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    out.extend_from_slice(&seg_cmd_size.to_le_bytes());
    push_cstr16(&mut out, ""); // segname
    out.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
    out.extend_from_slice(&vmsize.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // fileoff
    // MH_OBJECT: the segment's file size mirrors its vm size (section
    // offsets still point at the actual bytes).
    out.extend_from_slice(&vmsize.to_le_bytes()); // filesize
    out.extend_from_slice(&7u32.to_le_bytes()); // maxprot
    out.extend_from_slice(&7u32.to_le_bytes()); // initprot
    out.extend_from_slice(&nsects.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags

    section(
        &mut out, "__text", "__TEXT", text_addr, text.len() as u64, text_off as u32, 4,
        reloc_off as u32, (relocs.len() / 8) as u32,
        S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
    );
    section(
        &mut out, "__const", "__TEXT", const_addr, rodata.len() as u64, const_off as u32, 3,
        0, 0, 0,
    );
    section(
        &mut out, "__data", "__DATA", data_addr, data.len() as u64, data_off as u32, 3,
        0, 0, 0,
    );
    section(
        &mut out, "__bss", "__DATA", bss_addr, bss, 0, 3, 0, 0, S_ZEROFILL,
    );

    // LC_SYMTAB
    out.extend_from_slice(&LC_SYMTAB.to_le_bytes());
    out.extend_from_slice(&24u32.to_le_bytes());
    out.extend_from_slice(&(symoff as u32).to_le_bytes());
    out.extend_from_slice(&((syms.len() / 16) as u32).to_le_bytes());
    out.extend_from_slice(&(stroff as u32).to_le_bytes());
    out.extend_from_slice(&(strtab.len() as u32).to_le_bytes());

    // LC_DYSYMTAB
    out.extend_from_slice(&LC_DYSYMTAB.to_le_bytes());
    out.extend_from_slice(&80u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // ilocalsym
    out.extend_from_slice(&n_local.to_le_bytes());
    out.extend_from_slice(&n_local.to_le_bytes()); // iextdefsym
    out.extend_from_slice(&n_global.to_le_bytes());
    out.extend_from_slice(&(n_local + n_global).to_le_bytes()); // iundefsym
    out.extend_from_slice(&n_undef.to_le_bytes());
    for _ in 0..12 {
        out.extend_from_slice(&0u32.to_le_bytes()); // tocoff..undefined
    }

    debug_assert_eq!(out.len(), cmds_end);
    out.resize(text_off, 0);
    out.extend_from_slice(&text);
    out.resize(const_off, 0);
    out.extend_from_slice(&rodata);
    out.resize(data_off, 0);
    out.extend_from_slice(&data);
    out.resize(reloc_off, 0);
    out.extend_from_slice(&relocs);
    out.resize(symoff, 0);
    out.extend_from_slice(&syms);
    out.extend_from_slice(&strtab);
    Ok(out)
}

fn static_section(
    section: SectionKind,
    text: u64,
    rodata: u64,
    data: u64,
    bss: u64,
) -> (u8, u64) {
    match section {
        SectionKind::Text => (1, text),
        SectionKind::RoData => (2, rodata),
        SectionKind::Data => (3, data),
        SectionKind::Bss => (4, bss),
    }
}

fn push_cstr16(out: &mut Vec<u8>, s: &str) {
    let mut buf = [0u8; 16];
    let n = s.len().min(15);
    buf[..n].copy_from_slice(&s.as_bytes()[..n]);
    out.extend_from_slice(&buf);
}

#[allow(clippy::too_many_arguments)]
fn section(
    out: &mut Vec<u8>,
    sectname: &str,
    segname: &str,
    addr: u64,
    size: u64,
    offset: u32,
    align_pow2: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
) {
    push_cstr16(out, sectname);
    push_cstr16(out, segname);
    out.extend_from_slice(&addr.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&align_pow2.to_le_bytes());
    out.extend_from_slice(&reloff.to_le_bytes());
    out.extend_from_slice(&nreloc.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved1
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved3
}

#[cfg(test)]
mod tests {
    use super::*;
    use yana_codegen::{resolve_module, ResolveOptions, TargetInfo};

    fn module_of(src: &str) -> Module {
        let file = yana_parser::parse_ok(src);
        let out = resolve_module(
            &file,
            &TargetInfo::linux_x86_64(),
            &ResolveOptions::default(),
        );
        assert!(
            !out.diagnostics
                .iter()
                .any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
            "{:?}",
            out.diagnostics
        );
        out.module
    }

    fn obj(src: &str) -> Vec<u8> {
        let module = module_of(src);
        let enc = crate::assemble_text(&module, None).expect("encode");
        write_object(&module, &enc).expect("macho")
    }

    fn u32_at(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }

    #[test]
    fn writes_macho_header_and_sections() {
        let b = obj(
            r#"
fn f() { alt rax = 1; return; }
"#,
        );
        assert_eq!(u32_at(&b, 0), MH_MAGIC_64);
        assert_eq!(u32_at(&b, 4), CPU_TYPE_X86_64);
        assert_eq!(u32_at(&b, 12), MH_OBJECT);
        assert_eq!(u32_at(&b, 16), 3, "ncmds");
        // LC_SEGMENT_64 at 32, nsects at 32+64 = 96
        assert_eq!(u32_at(&b, 32), LC_SEGMENT_64);
        assert_eq!(u32_at(&b, 96), 4, "four sections");
        // First section name __text at 32+72
        assert_eq!(&b[104..110], b"__text");
    }

    #[test]
    fn emits_undefined_symbol_and_branch_relocation() {
        let b = obj(
            r#"
extern "C" fn ext();
fn f() { call ext; return; }
"#,
        );
        // Find LC_SYMTAB: header 32 + segment cmd (72+4*80) = 424.
        let symtab = 32 + 72 + 4 * 80;
        assert_eq!(u32_at(&b, symtab), LC_SYMTAB);
        let nsyms = u32_at(&b, symtab + 12);
        assert_eq!(nsyms, 2, "f + ext"); // f local, ext undefined
        let strsize = u32_at(&b, symtab + 20);
        let stroff = u32_at(&b, symtab + 16) as usize;
        let strtab = &b[stroff..stroff + strsize as usize];
        // The resolver applies `TargetInfo::symbol_prefix` ("_" on macOS).
        assert!(strtab.windows(4).any(|w| w == b"ext\0"), "ext in strtab");

        // __text section nreloc is at segment_cmd + 72 + 60
        let text_sect = 32 + 72;
        assert_eq!(u32_at(&b, text_sect + 60), 1, "one relocation");
        let reloff = u32_at(&b, text_sect + 56) as usize;
        let info = u32_at(&b, reloff + 4);
        assert_eq!((info >> 28) & 0xf, X86_64_RELOC_BRANCH);
        assert_eq!((info >> 24) & 1, 1, "pcrel");
    }

    #[test]
    fn rodata_and_bss_sizes_are_recorded() {
        let b = obj(
            r#"
bind s @ .rodata: [u8; 4] = b"abcd";
bind z @ .bss: [u8; 16];
fn f() { return; }
"#,
        );
        let text_sect = 32 + 72;
        let const_sect = text_sect + 80;
        let data_sect = const_sect + 80;
        let bss_sect = data_sect + 80;
        assert_eq!(&b[const_sect..const_sect + 7], b"__const");
        assert_eq!(u64::from_le_bytes(b[const_sect + 40..const_sect + 48].try_into().unwrap()), 4);
        assert_eq!(&b[bss_sect..bss_sect + 5], b"__bss");
        assert_eq!(u64::from_le_bytes(b[bss_sect + 40..bss_sect + 48].try_into().unwrap()), 16);
    }
}
