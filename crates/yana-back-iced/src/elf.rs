//! Minimal ELF64 writer: a statically-linked `ET_EXEC` (no external `ld`) and
//! a relocatable `ET_REL` object (for the NASM-oracle comparison and for
//! linking against libc/libSystem later).
//!
//! The executable layout follows the spike that proved the contract:
//! `.text` at 0x401000, `.rodata` at 0x402000, `.data` at 0x403000, `.bss` at
//! 0x404000, entry = the `#[entry]` function.

use std::collections::HashMap;

use yana_ast::place::SectionKind;
use yana_codegen::{Module, SymbolKind};

use crate::encode::{assemble_text, section_bytes, EncodedText, Layout};

// ELF constants
const ET_EXEC: u16 = 2;
const ET_REL: u16 = 1;
const EM_X86_64: u16 = 0x3e;
const EV_CURRENT: u32 = 1;

const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;

const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;

const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_OBJECT: u8 = 1;
const STT_SECTION: u8 = 3;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const R_X86_64_PC32: u32 = 2;
const R_X86_64_PLT32: u32 = 4;

/// Build a statically-linked executable ELF from a resolved module.
pub fn link_exe(module: &Module) -> Result<Vec<u8>, crate::encode::AsmError> {
    let layout = Layout::default_x86_64();
    let enc = assemble_text(module, Some(layout))?;

    let (rodata, _rodata_sz) = section_bytes_of(module, SectionKind::RoData);
    let (data, _data_sz) = section_bytes_of(module, SectionKind::Data);
    let bss_size = bss_size_of(module);

    let entry = layout.text_vaddr
        + enc.entry.ok_or_else(|| {
            crate::encode::AsmError::Layout("no #[entry] function — nothing to link as an executable".into())
        })?;

    let text = &enc.text;

    // Kernel requirement: for every PT_LOAD, p_offset ≡ p_vaddr (mod page).
    // Layout vaddrs are 0x1000-apart, so file offsets must be too.
    let mut out: Vec<u8> = Vec::new();

    // Physical file layout:
    //   [ehdr][phdr x4][pad→0x1000][.text][pad→0x2000][.rodata][pad→0x3000][.data]
    //   [.symtab][.strtab][.shstrtab][shdrs]
    let ehdr_size = 64usize;
    let phnum = 4usize;
    let phdr_size = 56usize;
    let page = 0x1000usize;

    // file offsets, congruent to their vaddrs mod page
    let text_off = page; // vaddr 0x401000
    let rodata_off = 2 * page; // vaddr 0x402000
    let data_off = 3 * page; // vaddr 0x403000
    let symtab_off = align(data_off + data.len(), 8);
    let _ = (ehdr_size, phnum, phdr_size);

    // Build symtab/strtab (local symbols first, then globals; sh_info = #locals)
    let mut symtab: Vec<u8> = Vec::new();
    let mut strtab: Vec<u8> = vec![0];
    let mut n_local = 1u32; // index 0 is the null symbol (local)

    // null symbol
    symtab.extend(sym_entry(0, 0, 0, 0, 0));

    // section symbols (optional but nice); we add text/rodata/data/bss as locals
    let sec_syms = add_section_symbols(&mut symtab, &mut strtab, &layout, text.len(), &rodata, &data, bss_size);
    n_local += sec_syms as u32;

    // function + static symbols from the module
    for (i, s) in module.symbols.iter().enumerate() {
        let name_off = intern(&mut strtab, &s.name);
        let global = s.exported;
        match &s.kind {
            SymbolKind::Function { .. } => {
                let off = enc.fn_offsets.get(&i).copied().unwrap_or(0);
                let info = (if global { STB_GLOBAL } else { STB_LOCAL } << 4) | STT_FUNC;
                let _ = info;
                let info = ((if global { STB_GLOBAL } else { STB_LOCAL }) << 4) | STT_FUNC;
                symtab.extend(sym_entry(name_off, layout.text_vaddr + off, 0, info, 1 /* .text */));
            }
            SymbolKind::Static { section, offset, size } => {
                let shndx = match section {
                    SectionKind::Text => 1,
                    SectionKind::RoData => 2,
                    SectionKind::Data => 3,
                    SectionKind::Bss => 4,
                };
                let vaddr = layout.vaddr_of(*section) + *offset;
                let info = ((if global { STB_GLOBAL } else { STB_LOCAL }) << 4) | STT_OBJECT;
                symtab.extend(sym_entry(name_off, vaddr, *size, info, shndx));
            }
            SymbolKind::Const { .. } | SymbolKind::ExternFn => {
                // consts have no runtime symbol; externs are undefined (SHN_UNDEF=0)
                if matches!(s.kind, SymbolKind::ExternFn) {
                    let info = (STB_GLOBAL << 4) | STT_FUNC;
                    symtab.extend(sym_entry(name_off, 0, 0, info, 0));
                }
            }
        }
        if !global {
            n_local += 1;
        }
    }

    let strtab_off = symtab_off + symtab.len();
    let shstrtab_off_placeholder = strtab_off + strtab.len();

    // shstrtab
    let mut shstrtab: Vec<u8> = Vec::new();
    let sh_names = [
        "", ".text", ".rodata", ".data", ".bss", ".symtab", ".strtab", ".shstrtab",
    ];
    let mut sh_name_off = Vec::new();
    for n in sh_names {
        sh_name_off.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(n.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_off = shstrtab_off_placeholder;
    let shdr_off = align(shstrtab_off + shstrtab.len(), 8);

    // ---- write ehdr ----
    out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&ET_EXEC.to_le_bytes());
    out.extend_from_slice(&EM_X86_64.to_le_bytes());
    out.extend_from_slice(&EV_CURRENT.to_le_bytes());
    out.extend_from_slice(&entry.to_le_bytes()); // e_entry
    out.extend_from_slice(&(ehdr_size as u64).to_le_bytes()); // e_phoff
    out.extend_from_slice(&(shdr_off as u64).to_le_bytes()); // e_shoff
    out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    out.extend_from_slice(&(ehdr_size as u16).to_le_bytes()); // e_ehsize
    out.extend_from_slice(&(phdr_size as u16).to_le_bytes()); // e_phentsize
    out.extend_from_slice(&(phnum as u16).to_le_bytes()); // e_phnum
    out.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
    out.extend_from_slice(&8u16.to_le_bytes()); // e_shnum (null + text + rodata + data + bss + symtab + strtab + shstrtab)
    out.extend_from_slice(&7u16.to_le_bytes()); // e_shstrndx (.shstrtab is index 7)

    // ---- program headers ----
    // PT_LOAD text (r-x)
    phdr(&mut out, PT_LOAD, PF_R | PF_X, text_off as u64, layout.text_vaddr, layout.text_vaddr, text.len() as u64, text.len() as u64, 0x1000);
    // PT_LOAD rodata (r--)
    if !rodata.is_empty() {
        phdr(&mut out, PT_LOAD, PF_R, rodata_off as u64, layout.rodata_vaddr, layout.rodata_vaddr, rodata.len() as u64, rodata.len() as u64, 0x1000);
    } else {
        phdr(&mut out, PT_LOAD, PF_R, rodata_off as u64, layout.rodata_vaddr, layout.rodata_vaddr, 0, 0, 0x1000);
    }
    // PT_LOAD data (rw-) filesz=data, memsz=data+bss
    let data_filesz = data.len() as u64;
    let data_memsz = data.len() as u64 + bss_size;
    phdr(&mut out, PT_LOAD, PF_R | PF_W, data_off as u64, layout.data_vaddr, layout.data_vaddr, data_filesz, data_memsz, 0x1000);
    // A fourth PT_LOAD is not needed; pad phnum expectation by reusing data seg.
    // We declared phnum=4 above — emit a null-ish PT_LOAD for .bss aliasing to
    // keep the count consistent (bss is covered by the data segment's memsz).
    phdr(&mut out, PT_LOAD, PF_R | PF_W, data_off as u64, layout.data_vaddr, layout.data_vaddr, data_filesz, data_memsz, 0x1000);

    while out.len() < text_off {
        out.push(0);
    }
    out.extend_from_slice(text);
    while out.len() < rodata_off {
        out.push(0);
    }
    out.extend_from_slice(&rodata);
    while out.len() < data_off {
        out.push(0);
    }
    out.extend_from_slice(&data);
    while out.len() < symtab_off {
        out.push(0);
    }
    out.extend_from_slice(&symtab);
    out.extend_from_slice(&strtab);
    out.extend_from_slice(&shstrtab);
    while out.len() < shdr_off {
        out.push(0);
    }

    // ---- section headers ----
    // 0 null
    shdr(&mut out, 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0);
    // 1 .text
    shdr(&mut out, sh_name_off[1], SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, layout.text_vaddr, text_off as u64, text.len() as u64, 0, 0, 16, 0);
    // 2 .rodata
    shdr(&mut out, sh_name_off[2], SHT_PROGBITS, SHF_ALLOC, layout.rodata_vaddr, rodata_off as u64, rodata.len() as u64, 0, 0, 1, 0);
    // 3 .data
    shdr(&mut out, sh_name_off[3], SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, layout.data_vaddr, data_off as u64, data.len() as u64, 0, 0, 8, 0);
    // 4 .bss (NOBITS)
    shdr(&mut out, sh_name_off[4], SHT_NOBITS, SHF_ALLOC | SHF_WRITE, layout.bss_vaddr, (data_off + data.len()) as u64, bss_size, 0, 0, 8, 0);
    // 5 .symtab
    shdr(&mut out, sh_name_off[5], SHT_SYMTAB, 0, 0, symtab_off as u64, symtab.len() as u64, 6 /*link=strtab*/, n_local, 8, 24);
    // 6 .strtab
    shdr(&mut out, sh_name_off[6], SHT_STRTAB, 0, 0, strtab_off as u64, strtab.len() as u64, 0, 0, 1, 0);
    // 7 .shstrtab
    shdr(&mut out, sh_name_off[7], SHT_STRTAB, 0, 0, shstrtab_off as u64, shstrtab.len() as u64, 0, 0, 1, 0);

    Ok(out)
}

fn align(x: usize, a: usize) -> usize {
    (x + a - 1) / a * a
}

fn section_bytes_of(module: &Module, kind: SectionKind) -> (Vec<u8>, u64) {
    for sec in &module.sections {
        if sec.kind == kind {
            return section_bytes(sec);
        }
    }
    (Vec::new(), 0)
}

fn bss_size_of(module: &Module) -> u64 {
    for sec in &module.sections {
        if sec.kind == SectionKind::Bss {
            return section_bytes(sec).1;
        }
    }
    0
}

fn add_section_symbols(
    symtab: &mut Vec<u8>,
    strtab: &mut Vec<u8>,
    layout: &Layout,
    text_len: usize,
    rodata: &[u8],
    data: &[u8],
    bss: u64,
) -> usize {
    let mut count = 0;
    for (name, shndx, vaddr, size) in [
        (".text", 1u16, layout.text_vaddr, text_len as u64),
        (".rodata", 2, layout.rodata_vaddr, rodata.len() as u64),
        (".data", 3, layout.data_vaddr, data.len() as u64),
        (".bss", 4, layout.bss_vaddr, bss),
    ] {
        let off = intern(strtab, name);
        let info = (STB_LOCAL << 4) | STT_SECTION;
        symtab.extend(sym_entry(off, vaddr, 0, info, shndx));
        count += 1;
    }
    count
}

fn intern(strtab: &mut Vec<u8>, name: &str) -> u32 {
    let off = strtab.len() as u32;
    strtab.extend_from_slice(name.as_bytes());
    strtab.push(0);
    off
}

fn sym_entry(name: u32, value: u64, size: u64, info: u8, shndx: u16) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[0..4].copy_from_slice(&name.to_le_bytes());
    b[4] = info;
    b[5] = 0; // st_other
    b[6..8].copy_from_slice(&shndx.to_le_bytes());
    b[8..16].copy_from_slice(&value.to_le_bytes());
    b[16..24].copy_from_slice(&size.to_le_bytes());
    b
}

fn shdr(
    out: &mut Vec<u8>,
    name: u32,
    ty: u32,
    flags: u64,
    addr: u64,
    off: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
) {
    out.extend_from_slice(&name.to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&addr.to_le_bytes());
    out.extend_from_slice(&off.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&link.to_le_bytes());
    out.extend_from_slice(&info.to_le_bytes());
    out.extend_from_slice(&align.to_le_bytes());
    out.extend_from_slice(&entsize.to_le_bytes());
}

fn phdr(
    out: &mut Vec<u8>,
    ptype: u32,
    flags: u32,
    off: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
) {
    out.extend_from_slice(&ptype.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&off.to_le_bytes());
    out.extend_from_slice(&vaddr.to_le_bytes());
    out.extend_from_slice(&paddr.to_le_bytes());
    out.extend_from_slice(&filesz.to_le_bytes());
    out.extend_from_slice(&memsz.to_le_bytes());
    out.extend_from_slice(&align.to_le_bytes());
}

/// Write a relocatable `ET_REL` object (`.o`) — used for the NASM-oracle
/// comparison (`ld` both objects, disassemble, compare). Symbol references that
/// could not be resolved at encode time become `.rela.text` entries.
pub fn write_object(module: &Module, enc: &EncodedText) -> Result<Vec<u8>, crate::encode::AsmError> {
    // Reuse the proven spike format: symtab + .rela.text from enc.patches.
    let mut shstrtab: Vec<u8> = Vec::new();
    let sh_names = ["", ".text", ".rodata", ".data", ".bss", ".rela.text", ".symtab", ".strtab", ".shstrtab"];
    let mut sh_name_off = Vec::new();
    for n in sh_names {
        sh_name_off.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(n.as_bytes());
        shstrtab.push(0);
    }

    let (rodata, _) = section_bytes_of(module, SectionKind::RoData);
    let (data, _) = section_bytes_of(module, SectionKind::Data);
    let bss = bss_size_of(module);

    let mut strtab: Vec<u8> = vec![0];
    let mut symtab: Vec<u8> = vec![0; 24]; // null symbol
    let mut n_local = 1u32;

    // section symbols
    for (name, shndx) in [(".text", 1u16), (".rodata", 2), (".data", 3), (".bss", 4)] {
        let off = intern(&mut strtab, name);
        let info = (STB_LOCAL << 4) | STT_SECTION;
        symtab.extend(sym_entry(off, 0, 0, info, shndx));
        n_local += 1;
    }
    // map module symbol index → ELF symtab index
    let mut elf_index: HashMap<usize, u32> = HashMap::new();
    let mut next_idx = 5u32;
    for (i, s) in module.symbols.iter().enumerate() {
        let off = intern(&mut strtab, &s.name);
        let (info, shndx, size) = match &s.kind {
            SymbolKind::Function { .. } => {
                (((if s.exported { STB_GLOBAL } else { STB_LOCAL }) << 4) | STT_FUNC, 1u16, 0u64)
            }
            SymbolKind::Static { section, .. } => {
                let sh = match section {
                    SectionKind::Text => 1,
                    SectionKind::RoData => 2,
                    SectionKind::Data => 3,
                    SectionKind::Bss => 4,
                };
                (((if s.exported { STB_GLOBAL } else { STB_LOCAL }) << 4) | STT_OBJECT, sh, 0u64)
            }
            SymbolKind::ExternFn => (((STB_GLOBAL) << 4) | STT_FUNC, 0u16, 0u64),
            SymbolKind::Const { .. } => (((STB_LOCAL) << 4) | STT_OBJECT, 0u16, 0u64),
        };
        let value = match &s.kind {
            SymbolKind::Function { .. } => enc.fn_offsets.get(&i).copied().unwrap_or(0),
            SymbolKind::Static { offset, .. } => *offset,
            _ => 0,
        };
        if (info >> 4) == STB_LOCAL as u8 {
            n_local += 1;
        }
        symtab.extend(sym_entry(off, value, size, info, shndx));
        elf_index.insert(i, next_idx);
        next_idx += 1;
    }

    // relocations
    let mut rela: Vec<u8> = Vec::new();
    for p in &enc.patches {
        let sym = *elf_index.get(&p.sym).ok_or_else(|| {
            crate::encode::AsmError::Layout(format!("patch references unknown symbol #{}", p.sym))
        })?;
        let rtype = match p.kind {
            crate::encode::RelocKind::Plt32 => R_X86_64_PLT32,
            crate::encode::RelocKind::Pc32 => R_X86_64_PC32,
            crate::encode::RelocKind::Abs32 | crate::encode::RelocKind::Abs64 => R_X86_64_PC32,
        };
        rela.extend_from_slice(&(p.at as u64).to_le_bytes());
        let r_info = ((sym as u64) << 32) | (rtype as u64);
        rela.extend_from_slice(&r_info.to_le_bytes());
        rela.extend_from_slice(&(p.addend as i64).to_le_bytes());
    }

    // layout
    let ehdr_size = 64u64;
    let mut off = ehdr_size;
    let text_off = off; off += enc.text.len() as u64;
    let rodata_off = off; off += rodata.len() as u64;
    let data_off = off; off += data.len() as u64;
    let rela_off = off; off += rela.len() as u64;
    let symtab_off = off; off += symtab.len() as u64;
    let strtab_off = off; off += strtab.len() as u64;
    let shstrtab_off = off; off += shstrtab.len() as u64;
    let shdr_off = off;
    let shnum = 9u16;

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&ET_REL.to_le_bytes());
    out.extend_from_slice(&EM_X86_64.to_le_bytes());
    out.extend_from_slice(&EV_CURRENT.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    out.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
    out.extend_from_slice(&shdr_off.to_le_bytes()); // e_shoff
    out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    out.extend_from_slice(&64u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // phentsize
    out.extend_from_slice(&0u16.to_le_bytes()); // phnum
    out.extend_from_slice(&64u16.to_le_bytes());
    out.extend_from_slice(&shnum.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes()); // shstrndx

    out.extend_from_slice(&enc.text);
    out.extend_from_slice(&rodata);
    out.extend_from_slice(&data);
    out.extend_from_slice(&rela);
    out.extend_from_slice(&symtab);
    out.extend_from_slice(&strtab);
    out.extend_from_slice(&shstrtab);

    // section headers
    shdr(&mut out, 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0);
    shdr(&mut out, sh_name_off[1], SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0, text_off, enc.text.len() as u64, 0, 0, 16, 0);
    shdr(&mut out, sh_name_off[2], SHT_PROGBITS, SHF_ALLOC, 0, rodata_off, rodata.len() as u64, 0, 0, 1, 0);
    shdr(&mut out, sh_name_off[3], SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 0, data_off, data.len() as u64, 0, 0, 8, 0);
    shdr(&mut out, sh_name_off[4], SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 0, data_off + data.len() as u64, bss, 0, 0, 8, 0);
    shdr(&mut out, sh_name_off[5], SHT_RELA, 0, 0, rela_off, rela.len() as u64, 6 /*symtab*/, 1 /*applies to .text*/, 8, 24);
    shdr(&mut out, sh_name_off[6], SHT_SYMTAB, 0, 0, symtab_off, symtab.len() as u64, 7 /*strtab*/, n_local, 8, 24);
    shdr(&mut out, sh_name_off[7], SHT_STRTAB, 0, 0, strtab_off, strtab.len() as u64, 0, 0, 1, 0);
    shdr(&mut out, sh_name_off[8], SHT_STRTAB, 0, 0, shstrtab_off, shstrtab.len() as u64, 0, 0, 1, 0);

    Ok(out)
}
