//! IR → x86-64 machine code via iced-x86.
//!
//! Encoding is fully explicit (spec §0): each [`Insn`] maps to exactly one
//! `iced_x86::Instruction`; the encoder never invents instructions.
//!
//! Two passes over each function body:
//! 1. **encode**: emit every instruction with placeholder targets (branches
//!    rel32, symbol displacements rip+disp32). All chosen encodings have
//!    length independent of displacement *values*, so offsets are final after
//!    this pass.
//! 2. **fixup**: rewrite branch/call rel32 fields and rip-relative symbol
//!    displacements in place.
//!
//! Symbol operands must be resolvable at encode time: executable mode gets a
//! [`Layout`] with fixed section vaddrs; object mode records [`PatchSite`]s
//! for the ELF relocation table instead.

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, FastFormatter, Instruction, MemoryOperand, Register,
};
use std::collections::HashMap;

use yana_ast::place::SectionKind;
use yana_ast::reg::{GprBase, Reg, RegSize};
use yana_codegen::{
    DataItem, Displacement, FnBody, Insn, Jcc, MemOp, Module, Operand, SectionData, SymbolKind,
    WideOp,
};

// ---------------------------------------------------------------------------
// public surface
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum AsmError {
    Encode(String),
    Layout(String),
    Unresolved(String),
}

impl std::fmt::Display for AsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsmError::Encode(m) => write!(f, "encode error: {m}"),
            AsmError::Layout(m) => write!(f, "layout error: {m}"),
            AsmError::Unresolved(m) => write!(f, "unresolved reference: {m}"),
        }
    }
}
impl std::error::Error for AsmError {}

/// Fixed virtual addresses per section (executable mode).
#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub base: u64,
    pub text_vaddr: u64,
    pub rodata_vaddr: u64,
    pub data_vaddr: u64,
    pub bss_vaddr: u64,
}

impl Layout {
    /// A simple static layout: text first, then rodata, data, bss (all 4K apart
    /// with headroom for growth — sizes are patched after encoding).
    pub fn default_x86_64() -> Layout {
        Layout {
            base: 0x400000,
            text_vaddr: 0x401000,
            rodata_vaddr: 0x402000,
            data_vaddr: 0x403000,
            bss_vaddr: 0x404000,
        }
    }

    pub fn vaddr_of(&self, s: SectionKind) -> u64 {
        match s {
            SectionKind::Text => self.text_vaddr,
            SectionKind::RoData => self.rodata_vaddr,
            SectionKind::Data => self.data_vaddr,
            SectionKind::Bss => self.bss_vaddr,
        }
    }
}

/// A relocation site recorded for object-file output.
#[derive(Debug, Clone)]
pub struct PatchSite {
    /// Offset of the field to patch, within `.text`.
    pub at: usize,
    /// Field width: 4 (disp32/rel32) or 8 (imm64).
    pub width: u8,
    pub kind: RelocKind,
    /// Target symbol index in `module.symbols`.
    pub sym: usize,
    /// Addend (PC32 wants −4).
    pub addend: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    /// rip-relative field: value = S + A − P.
    Pc32,
    /// `call` to an external function.
    Plt32,
    /// Absolute 32-bit (imm sign-extended).
    Abs32,
    /// Absolute 64-bit (`mov r64, imm64` of a symbol address).
    Abs64,
}

/// Fully encoded text + everything needed to write an ELF.
pub struct EncodedText {
    pub text: Vec<u8>,
    /// Symbol index → offset within text (for functions defined here).
    pub fn_offsets: HashMap<usize, u64>,
    /// Offset of the `#[entry]` function within text.
    pub entry: Option<u64>,
    /// Relocation sites (object mode / unresolved externals).
    pub patches: Vec<PatchSite>,
}

/// Assemble all function bodies into one `.text` image.
///
/// `layout` = `Some` resolves every symbol against fixed section vaddrs (exe
/// mode); `None` records [`PatchSite`]s for external calls instead (object
/// mode). Branch lengths are value-independent (rel32), so a single encode
/// pass per body plus a fixup pass is exact.
pub fn assemble_text(module: &Module, layout: Option<Layout>) -> Result<EncodedText, AsmError> {
    let mut text: Vec<u8> = Vec::new();
    let mut fn_offsets: HashMap<usize, u64> = HashMap::new();
    let mut entry: Option<u64> = None;
    let mut patches: Vec<PatchSite> = Vec::new();

    // symbol vaddr table: statics from the layout, functions filled in below
    let mut sym_vaddrs: HashMap<usize, Option<u64>> = HashMap::new();
    for (i, s) in module.symbols.iter().enumerate() {
        let v = match &s.kind {
            SymbolKind::Static { section, offset, .. } => {
                layout.map(|l| l.vaddr_of(*section) + *offset)
            }
            _ => None,
        };
        sym_vaddrs.insert(i, v);
    }

    // Two sweeps: first compute every function's start ip (bodies in order),
    // then encode. Function starts only depend on body sizes, and body sizes
    // don't depend on displacement values (all rel32/disp32) — so one sizing
    // sweep with dummy instructions suffices.
    let base = layout.map(|l| l.text_vaddr).unwrap_or(0);
    let mut fn_starts: HashMap<usize, u64> = HashMap::new();
    let mut ip = base;
    for body in &module.bodies {
        fn_starts.insert(body.symbol, ip);
        // size this body with dummy encodings
        let mut enc = Encoder::new(64);
        for ins in &body.insns {
            if let Some(i) = build_insn(&ins.insn, &sym_vaddrs, layout, base)? {
                let n = enc.encode(&i, ip).map_err(|e| AsmError::Encode(e.to_string()))?;
                enc.take_buffer();
                ip += n as u64;
            }
        }
    }
    let text_end = ip;

    // now functions have addresses; record them
    for (sym_idx, start_ip) in &fn_starts {
        sym_vaddrs.insert(*sym_idx, Some(*start_ip));
    }
    if let Some(e) = module.entry {
        entry = fn_starts.get(&e).map(|v| v - base);
    }
    for (sym_idx, off) in &fn_starts {
        fn_offsets.insert(*sym_idx, *off - base);
    }

    // real encode
    let mut enc = Encoder::new(64);
    let mut ip = base;
    // fixups: (text offset of the 4-byte field, what to write)
    let mut fixups: Vec<(usize, Fixup)> = Vec::new();

    for body in &module.bodies {
        // label → target ip
        let mut label_ips: HashMap<usize, u64> = HashMap::new();
        // compute instruction ips for this body
        let mut insn_ips: Vec<u64> = Vec::with_capacity(body.insns.len());
        {
            let mut cur = fn_starts[&body.symbol];
            let mut enc2 = Encoder::new(64);
            for ins in &body.insns {
                insn_ips.push(cur);
                if let Some(i) = build_insn(&ins.insn, &sym_vaddrs, layout, base)? {
                    let n = enc2.encode(&i, cur).map_err(|e| AsmError::Encode(e.to_string()))?;
                    enc2.take_buffer();
                    cur += n as u64;
                }
            }
        }
        for def in &body.label_defs {
            let at = def.at_insn.min(insn_ips.len());
            let lip = if at < insn_ips.len() { insn_ips[at] } else { text_end_at(&fn_starts, body, text_end) };
            label_ips.insert(label_index(body, &def.name), lip);
        }

        for (idx, ins) in body.insns.iter().enumerate() {
            let Some(mut i) = build_insn(&ins.insn, &sym_vaddrs, layout, base)? else {
                continue; // zero-byte instruction (lowered `align` with pad 0)
            };
            // Branch targets are resolved before encoding (rel32 length is
            // value-independent), so the encoder writes the correct field.
            let call_sym = match &ins.insn {
                Insn::Jmp { label } | Insn::Jcc { label, .. } => {
                    let target = *label_ips.get(label).ok_or_else(|| {
                        AsmError::Unresolved(format!("label index {label} has no definition"))
                    })?;
                    set_branch_target(&mut i, target);
                    None
                }
                Insn::Call { sym, .. } => Some(*sym),
                _ => None,
            };
            let n = enc.encode(&i, ip).map_err(|e| AsmError::Encode(e.to_string()))?;
            let buf = enc.take_buffer();
            if let Some(sym) = call_sym {
                let field_off = text.len() + n - 4; // rel32 is the last field
                match sym_vaddrs.get(&sym).copied().flatten() {
                    Some(v) => fixups.push((field_off, Fixup::Rel32 { target: v, next_ip: ip + n as u64 })),
                    None if layout.is_none() => patches.push(PatchSite {
                        at: field_off,
                        width: 4,
                        kind: RelocKind::Plt32,
                        sym,
                        addend: -4,
                    }),
                    None => {
                        return Err(AsmError::Unresolved(format!(
                            "call to undefined symbol `{}`",
                            module.symbols[sym].name
                        )))
                    }
                }
            }
            // LeaSym rip-relative fixup: field is the disp32 at end
            if let Insn::LeaSym { sym, add, .. } = &ins.insn {
                let field_off = text.len() + n - 4;
                match sym_vaddrs.get(sym).copied().flatten() {
                    Some(v) => fixups.push((field_off, Fixup::Rip32 { target: v as i64 + *add, next_ip: ip + n as u64 })),
                    None if layout.is_none() => patches.push(PatchSite {
                        at: field_off,
                        width: 4,
                        kind: RelocKind::Pc32,
                        sym: *sym,
                        addend: *add - 4,
                    }),
                    None => {
                        return Err(AsmError::Unresolved(format!(
                            "lea of undefined symbol `{}`",
                            module.symbols[*sym].name
                        )))
                    }
                }
            }
            // rip-relative memory with symbol disp: disp32 sits before any
            // immediate; for the MVP instruction set (mov/add/... with Sym
            // disp) disp32 is also the last 4 bytes when there is no imm.
            if let Insn::Mov { src: Operand::Mem(m), .. } | Insn::Add { src: Operand::Mem(m), .. }
                | Insn::Sub { src: Operand::Mem(m), .. } | Insn::Cmp { b: Operand::Mem(m), .. } = &ins.insn
            {
                if let Displacement::Sym { sym, add } = &m.disp {
                    if m.index.is_none() {
                        let field_off = text.len() + n - 4;
                        if let Some(v) = sym_vaddrs.get(sym).copied().flatten() {
                            fixups.push((field_off, Fixup::Rip32 { target: v as i64 + *add, next_ip: ip + n as u64 }));
                        } else if layout.is_none() {
                            patches.push(PatchSite {
                                at: field_off,
                                width: 4,
                                kind: RelocKind::Pc32,
                                sym: *sym,
                                addend: *add - 4,
                            });
                        } else {
                            return Err(AsmError::Unresolved(format!(
                                "memory reference to undefined symbol `{}`",
                                module.symbols[*sym].name
                            )));
                        }
                    }
                }
            }
            text.extend_from_slice(&buf);
            ip += n as u64;
        }
    }

    // apply fixups
    for (off, f) in fixups {
        let v = match f {
            Fixup::Rel32 { target, next_ip } => target as i64 - next_ip as i64,
            Fixup::Rip32 { target, next_ip } => target - next_ip as i64,
        };
        if !fits_i32(v) {
            return Err(AsmError::Encode(format!("displacement {v} exceeds i32")));
        }
        text[off..off + 4].copy_from_slice(&(v as i32).to_le_bytes());
    }

    Ok(EncodedText { text, fn_offsets, entry, patches })
}

fn text_end_at(fn_starts: &HashMap<usize, u64>, _body: &FnBody, text_end: u64) -> u64 {
    let _ = fn_starts;
    text_end
}

fn label_index(body: &FnBody, name: &str) -> usize {
    body.label_defs.iter().position(|d| d.name == name).unwrap_or(usize::MAX)
}

enum Fixup {
    Rel32 { target: u64, next_ip: u64 },
    Rip32 { target: i64, next_ip: u64 },
}

fn fits_i32(v: i64) -> bool {
    v >= i32::MIN as i64 && v <= i32::MAX as i64
}

fn set_branch_target(i: &mut Instruction, target: u64) {
    i.set_near_branch64(target);
}

// ---------------------------------------------------------------------------
// instruction building
// ---------------------------------------------------------------------------

fn build_insn(
    ins: &Insn,
    sym_vaddrs: &HashMap<usize, Option<u64>>,
    layout: Option<Layout>,
    base: u64,
) -> Result<Option<Instruction>, AsmError> {
    // A lowered `align` that needs no padding encodes to zero bytes (§4.3).
    if let Insn::StackPad { pad: 0 } = ins {
        return Ok(None);
    }
    build_insn_inner(ins, sym_vaddrs, layout, base).map(Some)
}

fn build_insn_inner(
    ins: &Insn,
    sym_vaddrs: &HashMap<usize, Option<u64>>,
    layout: Option<Layout>,
    base: u64,
) -> Result<Instruction, AsmError> {
    let resolve_sym = |sym: usize, add: i64| -> Result<i64, AsmError> {
        match sym_vaddrs.get(&sym).copied().flatten() {
            Some(v) => Ok(v as i64 + add),
            None => Err(AsmError::Unresolved(format!("symbol #{sym} has no address yet"))),
        }
    };
    let mem_op = |m: &MemOp| -> Result<MemoryOperand, AsmError> {
        let base = m.base.map(to_iced_reg).transpose()?.unwrap_or(Register::None);
        let index = m.index.map(to_iced_reg).transpose()?.unwrap_or(Register::None);
        let (disp, rip) = match &m.disp {
            Displacement::Const(c) => (*c, false),
            Displacement::Sym { sym, add } => (resolve_sym(*sym, *add)?, true),
        };
        if rip || m.base == Some(Reg::Rip) {
            Ok(MemoryOperand::new(Register::RIP, Register::None, 1, disp, 4, false, Register::None))
        } else {
            // NOTE: in 64-bit addressing iced's displ_size is {0,1,8} — 8 means
            // disp32 (4 is only valid for 32-bit addressing and errors out).
            let disp_size = if disp == 0 && base != Register::None { 0 } else { 8 };
            Ok(MemoryOperand::new(base, index, m.scale as u32, disp, disp_size, false, Register::None))
        }
    };
    let op = |o: &Operand| -> Result<IcedOp, AsmError> {
        Ok(match o {
            Operand::Reg(r) => IcedOp::Reg(to_iced_reg(*r)?),
            Operand::Imm(v) => IcedOp::Imm(*v),
            Operand::Mem(m) => IcedOp::Mem(mem_op(m)?),
            Operand::Sym { sym, add } => IcedOp::Imm(resolve_sym(*sym, *add)?),
        })
    };

    match ins {
        Insn::Mov { dst, src, size } => {
            let d = op(dst)?;
            let s = op(src)?;
            build_mov(d, s, *size)
        }
        Insn::Movzx { dst, src, src_size, dst_size } => {
            let code = movzx_code(*dst_size, *src_size)?;
            instr_reg_rm(code, to_iced_reg(*dst)?, op(src)?)
        }
        Insn::Movsx { dst, src, src_size, dst_size } => {
            let code = movsx_code(*dst_size, *src_size)?;
            instr_reg_rm(code, to_iced_reg(*dst)?, op(src)?)
        }
        Insn::Lea { dst, addr } => {
            let mo = mem_op(addr)?;
            Instruction::with2(Code::Lea_r64_m, to_iced_reg(*dst)?, mo).map_err(enc_err)
        }
        Insn::LeaSym { dst, .. } => {
            // `lea dst, [rip + disp32]`, disp32=0 placeholder; the fixup pass
            // rewrites the field once the instruction's ip is known.
            let mo = MemoryOperand::new(Register::RIP, Register::None, 1, 0, 4, false, Register::None);
            Instruction::with2(Code::Lea_r64_m, to_iced_reg(*dst)?, mo).map_err(enc_err)
        }
        Insn::Push { src, size } => {
            let s = op(src)?;
            match s {
                IcedOp::Reg(r) => Instruction::with1(push_r(*size), r).map_err(enc_err),
                IcedOp::Mem(m) => Instruction::with1(push_rm(*size), m).map_err(enc_err),
                IcedOp::Imm(v) => Instruction::with1(push_imm(*size), v as i32).map_err(enc_err),
            }
        }
        Insn::Pop { dst, size } => {
            let d = op(dst)?;
            match d {
                IcedOp::Reg(r) => Instruction::with1(pop_r(*size), r).map_err(enc_err),
                IcedOp::Mem(m) => Instruction::with1(pop_rm(*size), m).map_err(enc_err),
                IcedOp::Imm(_) => Err(AsmError::Encode("pop: immediate not allowed".into())),
            }
        }
        Insn::StackSlot { grow } => {
            // `_` slot (§4.3): `lea rsp, [rsp ∓ 8]` — flags untouched
            // (displ_size 8 = disp32 in 64-bit addressing; 4 would be invalid)
            let disp = if *grow { -8i64 } else { 8 };
            let mo = MemoryOperand::new(Register::RSP, Register::None, 1, disp, 8, false, Register::None);
            Instruction::with2(Code::Lea_r64_m, Register::RSP, mo).map_err(enc_err)
        }
        // `align N;` must be lowered to StackPad by the analysis pass (§14.3)
        // before codegen — a survivor is a pipeline bug, not a user error.
        Insn::StackAlign { align } => Err(AsmError::Encode(format!(
            "unlowered `align {align}` reached the iced backend — run yana_analysis::analyze first"
        ))),
        Insn::StackPad { pad } => {
            // lowered `align N;`: `lea rsp, [rsp-pad]`, flags untouched (§4.3).
            // pad == 0 is intercepted by the build_insn wrapper (zero bytes).
            let mo = MemoryOperand::new(
                Register::RSP,
                Register::None,
                1,
                -(*pad as i64),
                8, // disp32 in 64-bit addressing (see StackSlot note)
                false,
                Register::None,
            );
            Instruction::with2(Code::Lea_r64_m, Register::RSP, mo).map_err(enc_err)
        }
        Insn::Xchg { a, b, size } => {
            let x = op(a)?;
            let y = op(b)?;
            let code = xchg_code(*size)?;
            match (x, y) {
                (IcedOp::Reg(r), IcedOp::Reg(r2)) => Instruction::with2(code, r, r2).map_err(enc_err),
                (IcedOp::Mem(m), IcedOp::Reg(r)) => Instruction::with2(code, m, r).map_err(enc_err),
                _ => Err(AsmError::Encode("xchg: unsupported operands".into())),
            }
        }
        Insn::Add { dst, src, size } => arith(dst, src, *size, Arith::Add, op),
        Insn::Sub { dst, src, size } => arith(dst, src, *size, Arith::Sub, op),
        Insn::And { dst, src, size } => arith(dst, src, *size, Arith::And, op),
        Insn::Or { dst, src, size } => arith(dst, src, *size, Arith::Or, op),
        Insn::Xor { dst, src, size } => arith(dst, src, *size, Arith::Xor, op),
        Insn::Shl { dst, src, size } => shift(dst, src, *size, false, op),
        Insn::Shr { dst, src, size } => shift(dst, src, *size, true, op),
        Insn::Imul2 { dst, src, size } => {
            let d = op(dst)?;
            let s = op(src)?;
            let code = match size {
                64 => Code::Imul_r64_rm64,
                32 => Code::Imul_r32_rm32,
                16 => Code::Imul_r16_rm16,
                _ => return Err(AsmError::Encode("imul2: bad size".into())),
            };
            match shape2(&d, &s) {
                ("r", "r") | ("r", "m") => instr2(code, d, s),
                ("r", "i") => {
                    let c3 = match size {
                        64 => Code::Imul_r64_rm64_imm32,
                        32 => Code::Imul_r32_rm32_imm32,
                        16 => Code::Imul_r16_rm16_imm16,
                        _ => unreachable!(),
                    };
                    if let (IcedOp::Reg(r), IcedOp::Imm(v)) = (d, s) {
                        Instruction::with3(c3, r, r, v as i32).map_err(enc_err)
                    } else {
                        unreachable!()
                    }
                }
                _ => Err(AsmError::Encode("imul2: unsupported operands".into())),
            }
        }
        Insn::Neg { dst, size } => unary(unary_code(Unary::Neg, *size)?, op(dst)?),
        Insn::Not { dst, size } => unary(unary_code(Unary::Not, *size)?, op(dst)?),
        Insn::Inc { dst, size } => unary(unary_code(Unary::Inc, *size)?, op(dst)?),
        Insn::Dec { dst, size } => unary(unary_code(Unary::Dec, *size)?, op(dst)?),
        Insn::Cmp { a, b, size } => {
            let x = op(a)?;
            let y = op(b)?;
            let code = match shape2(&x, &y) {
                ("r", "r") | ("m", "r") => cmp_rm_r(*size)?,
                ("r", "m") => cmp_r_rm(*size)?,
                ("r", "i") | ("m", "i") => cmp_rm_imm(*size)?,
                _ => return Err(AsmError::Encode("cmp: unsupported operands".into())),
            };
            instr2(code, x, y)
        }
        Insn::MulWide { src, signed, size } => {
            let code = if *signed { imul_wide(*size)? } else { mul_code(*size)? };
            unary(code, op(src)?)
        }
        Insn::DivWide { src, op: wop, size } => {
            let code = match wop {
                WideOp::Unsigned => div_code(*size)?,
                WideOp::Signed => idiv_code(*size)?,
            };
            unary(code, op(src)?)
        }
        Insn::ExtendPair { signed, size } => {
            if *signed {
                let code = match size {
                    64 => Code::Cqo,
                    32 => Code::Cdq,
                    _ => return Err(AsmError::Encode("extend-pair: bad size".into())),
                };
                zero_op(code)
            } else {
                // xor edx,edx / xor rdx,rdx
                let (code, r) = if *size == 32 {
                    (Code::Xor_rm32_r32, Register::EDX)
                } else {
                    (Code::Xor_rm64_r64, Register::RDX)
                };
                Instruction::with2(code, r, r).map_err(enc_err)
            }
        }
        Insn::Jmp { .. } => Instruction::with_branch(Code::Jmp_rel32_64, 0).map_err(enc_err),
        Insn::Jcc { cc, .. } => Instruction::with_branch(jcc_code(*cc), 0).map_err(enc_err),
        Insn::Call { .. } => Instruction::with_branch(Code::Call_rel32_64, 0).map_err(enc_err),
        Insn::Syscall => zero_op(Code::Syscall),
        Insn::Ret => zero_op(Code::Retnq),
        Insn::Int3 => zero_op(Code::Int3),
        Insn::Nop => zero_op(Code::Nopd),
    }
}

fn zero_op(code: Code) -> Result<Instruction, AsmError> {
    let mut i = Instruction::default();
    i.set_code(code);
    Ok(i)
}

fn enc_err(e: iced_x86::IcedError) -> AsmError {
    AsmError::Encode(e.to_string())
}

enum IcedOp {
    Reg(Register),
    Mem(MemoryOperand),
    Imm(i64),
}

enum Arith {
    Add,
    Sub,
    And,
    Or,
    Xor,
}

enum Unary {
    Neg,
    Not,
    Inc,
    Dec,
}

fn instr2(code: Code, a: IcedOp, b: IcedOp) -> Result<Instruction, AsmError> {
    match (a, b) {
        (IcedOp::Reg(x), IcedOp::Reg(y)) => Instruction::with2(code, x, y).map_err(enc_err),
        (IcedOp::Reg(x), IcedOp::Mem(y)) => Instruction::with2(code, x, y).map_err(enc_err),
        (IcedOp::Mem(x), IcedOp::Reg(y)) => Instruction::with2(code, x, y).map_err(enc_err),
        (IcedOp::Reg(x), IcedOp::Imm(y)) => Instruction::with2(code, x, y as i32).map_err(enc_err),
        (IcedOp::Mem(x), IcedOp::Imm(y)) => Instruction::with2(code, x, y as i32).map_err(enc_err),
        _ => Err(AsmError::Encode("instr2: bad operand combination".into())),
    }
}

/// Shape tag for code selection: (dst-kind, src-kind).
fn shape2(a: &IcedOp, b: &IcedOp) -> (&'static str, &'static str) {
    let k = |o: &IcedOp| match o {
        IcedOp::Reg(_) => "r",
        IcedOp::Mem(_) => "m",
        IcedOp::Imm(_) => "i",
    };
    (k(a), k(b))
}

fn instr_reg_rm(code: Code, d: Register, s: IcedOp) -> Result<Instruction, AsmError> {
    match s {
        IcedOp::Reg(r) => Instruction::with2(code, d, r).map_err(enc_err),
        IcedOp::Mem(m) => Instruction::with2(code, d, m).map_err(enc_err),
        IcedOp::Imm(_) => Err(AsmError::Encode("movzx/movsx: immediate source not allowed".into())),
    }
}

fn build_mov(d: IcedOp, s: IcedOp, size: u32) -> Result<Instruction, AsmError> {
    match shape2(&d, &s) {
        ("r", "r") => instr2(mov_rm_r(size)?, d, s),
        ("r", "m") => instr2(mov_r_rm(size)?, d, s),
        ("m", "r") => instr2(mov_rm_r(size)?, d, s),
        ("r", "i") => {
            if let (IcedOp::Reg(r), IcedOp::Imm(v)) = (&d, &s) {
                if size == 64 && !fits_i32(*v) {
                    return Instruction::with2(Code::Mov_r64_imm64, *r, *v).map_err(enc_err);
                }
            }
            instr2(mov_rm_imm(size)?, d, s)
        }
        ("m", "i") => instr2(mov_rm_imm(size)?, d, s),
        _ => Err(AsmError::Encode("mov: unsupported operand shapes".into())),
    }
}

fn arith(
    dst: &Operand,
    src: &Operand,
    size: u32,
    a: Arith,
    op: impl Fn(&Operand) -> Result<IcedOp, AsmError>,
) -> Result<Instruction, AsmError> {
    let d = op(dst)?;
    let s = op(src)?;
    let code = match shape2(&d, &s) {
        ("r", "r") => alu_rm_r(size, &a)?,
        ("m", "r") => alu_rm_r(size, &a)?,
        ("r", "m") => alu_r_rm(size, &a)?,
        ("r", "i") | ("m", "i") => alu_rm_imm(size, &a)?,
        _ => {
            return Err(AsmError::Encode(
                "two memory operands need register staging on x86 (§4.1: one instruction per line)".to_string(),
            ))
        }
    };
    instr2(code, d, s)
}

fn shift(
    dst: &Operand,
    src: &Operand,
    size: u32,
    logical: bool,
    op: impl Fn(&Operand) -> Result<IcedOp, AsmError>,
) -> Result<Instruction, AsmError> {
    let d = op(dst)?;
    let s = op(src)?;
    match s {
        IcedOp::Imm(v) => {
            let code = shift_imm_code(size, logical)?;
            // iced has no With2<_, u8>; u32 works and the encoder writes only
            // the imm8 field dictated by the Code.
            match d {
                IcedOp::Reg(r) => Instruction::with2(code, r, v as u32).map_err(enc_err),
                IcedOp::Mem(m) => Instruction::with2(code, m, v as u32).map_err(enc_err),
                IcedOp::Imm(_) => Err(AsmError::Encode("shift: bad dst".into())),
            }
        }
        IcedOp::Reg(r) if r == Register::CL => {
            let code = shift_cl_code(size, logical)?;
            match d {
                IcedOp::Reg(rd) => Instruction::with2(code, rd, Register::CL).map_err(enc_err),
                IcedOp::Mem(m) => Instruction::with2(code, m, Register::CL).map_err(enc_err),
                IcedOp::Imm(_) => Err(AsmError::Encode("shift: bad dst".into())),
            }
        }
        _ => Err(AsmError::Encode("shift: source must be an immediate or cl (§4.1)".into())),
    }
}

fn unary(code: Code, d: IcedOp) -> Result<Instruction, AsmError> {
    match d {
        IcedOp::Reg(r) => Instruction::with1(code, r).map_err(enc_err),
        IcedOp::Mem(m) => Instruction::with1(code, m).map_err(enc_err),
        IcedOp::Imm(_) => Err(AsmError::Encode("unary: immediate not allowed".into())),
    }
}

// ---------------------------------------------------------------------------
// Code tables — the single source of truth for opcode selection per size.
// ---------------------------------------------------------------------------

fn mov_rm_r(size: u32) -> Result<Code, AsmError> {
    Ok(match size {
        64 => Code::Mov_rm64_r64, 32 => Code::Mov_rm32_r32,
        16 => Code::Mov_rm16_r16, 8 => Code::Mov_rm8_r8,
        _ => return Err(AsmError::Encode(format!("mov: bad size {size}"))),
    })
}
fn mov_r_rm(size: u32) -> Result<Code, AsmError> {
    Ok(match size {
        64 => Code::Mov_r64_rm64, 32 => Code::Mov_r32_rm32,
        16 => Code::Mov_r16_rm16, 8 => Code::Mov_r8_rm8,
        _ => return Err(AsmError::Encode(format!("mov: bad size {size}"))),
    })
}
fn mov_rm_imm(size: u32) -> Result<Code, AsmError> {
    Ok(match size {
        64 => Code::Mov_rm64_imm32, 32 => Code::Mov_rm32_imm32,
        16 => Code::Mov_rm16_imm16, 8 => Code::Mov_rm8_imm8,
        _ => return Err(AsmError::Encode(format!("mov imm: bad size {size}"))),
    })
}
fn alu_rm_r(size: u32, a: &Arith) -> Result<Code, AsmError> {
    Ok(match (a, size) {
        (Arith::Add, 64) => Code::Add_rm64_r64, (Arith::Add, 32) => Code::Add_rm32_r32,
        (Arith::Add, 16) => Code::Add_rm16_r16, (Arith::Add, 8) => Code::Add_rm8_r8,
        (Arith::Sub, 64) => Code::Sub_rm64_r64, (Arith::Sub, 32) => Code::Sub_rm32_r32,
        (Arith::Sub, 16) => Code::Sub_rm16_r16, (Arith::Sub, 8) => Code::Sub_rm8_r8,
        (Arith::And, 64) => Code::And_rm64_r64, (Arith::And, 32) => Code::And_rm32_r32,
        (Arith::And, 16) => Code::And_rm16_r16, (Arith::And, 8) => Code::And_rm8_r8,
        (Arith::Or, 64) => Code::Or_rm64_r64, (Arith::Or, 32) => Code::Or_rm32_r32,
        (Arith::Or, 16) => Code::Or_rm16_r16, (Arith::Or, 8) => Code::Or_rm8_r8,
        (Arith::Xor, 64) => Code::Xor_rm64_r64, (Arith::Xor, 32) => Code::Xor_rm32_r32,
        (Arith::Xor, 16) => Code::Xor_rm16_r16, (Arith::Xor, 8) => Code::Xor_rm8_r8,
        _ => return Err(AsmError::Encode("alu: bad size".into())),
    })
}
fn alu_r_rm(size: u32, a: &Arith) -> Result<Code, AsmError> {
    Ok(match (a, size) {
        (Arith::Add, 64) => Code::Add_r64_rm64, (Arith::Add, 32) => Code::Add_r32_rm32,
        (Arith::Sub, 64) => Code::Sub_r64_rm64, (Arith::Sub, 32) => Code::Sub_r32_rm32,
        (Arith::And, 64) => Code::And_r64_rm64, (Arith::And, 32) => Code::And_r32_rm32,
        (Arith::Or, 64) => Code::Or_r64_rm64, (Arith::Or, 32) => Code::Or_r32_rm32,
        (Arith::Xor, 64) => Code::Xor_r64_rm64, (Arith::Xor, 32) => Code::Xor_r32_rm32,
        _ => return Err(AsmError::Encode("alu r,rm: unsupported (8/16-bit forms use rm,r with reg staging)".into())),
    })
}
fn alu_rm_imm(size: u32, a: &Arith) -> Result<Code, AsmError> {
    Ok(match (a, size) {
        (Arith::Add, 64) => Code::Add_rm64_imm32, (Arith::Add, 32) => Code::Add_rm32_imm32,
        (Arith::Add, 16) => Code::Add_rm16_imm16, (Arith::Add, 8) => Code::Add_rm8_imm8,
        (Arith::Sub, 64) => Code::Sub_rm64_imm32, (Arith::Sub, 32) => Code::Sub_rm32_imm32,
        (Arith::Sub, 16) => Code::Sub_rm16_imm16, (Arith::Sub, 8) => Code::Sub_rm8_imm8,
        (Arith::And, 64) => Code::And_rm64_imm32, (Arith::And, 32) => Code::And_rm32_imm32,
        (Arith::And, 16) => Code::And_rm16_imm16, (Arith::And, 8) => Code::And_rm8_imm8,
        (Arith::Or, 64) => Code::Or_rm64_imm32, (Arith::Or, 32) => Code::Or_rm32_imm32,
        (Arith::Or, 16) => Code::Or_rm16_imm16, (Arith::Or, 8) => Code::Or_rm8_imm8,
        (Arith::Xor, 64) => Code::Xor_rm64_imm32, (Arith::Xor, 32) => Code::Xor_rm32_imm32,
        (Arith::Xor, 16) => Code::Xor_rm16_imm16, (Arith::Xor, 8) => Code::Xor_rm8_imm8,
        _ => return Err(AsmError::Encode("alu imm: bad size".into())),
    })
}
fn cmp_rm_r(size: u32) -> Result<Code, AsmError> {
    Ok(match size {
        64 => Code::Cmp_rm64_r64, 32 => Code::Cmp_rm32_r32,
        16 => Code::Cmp_rm16_r16, 8 => Code::Cmp_rm8_r8,
        _ => return Err(AsmError::Encode("cmp: bad size".into())),
    })
}
fn cmp_r_rm(size: u32) -> Result<Code, AsmError> {
    Ok(match size {
        64 => Code::Cmp_r64_rm64, 32 => Code::Cmp_r32_rm32,
        16 => Code::Cmp_r16_rm16, 8 => Code::Cmp_r8_rm8,
        _ => return Err(AsmError::Encode("cmp: bad size".into())),
    })
}
fn cmp_rm_imm(size: u32) -> Result<Code, AsmError> {
    Ok(match size {
        64 => Code::Cmp_rm64_imm32, 32 => Code::Cmp_rm32_imm32,
        16 => Code::Cmp_rm16_imm16, 8 => Code::Cmp_rm8_imm8,
        _ => return Err(AsmError::Encode("cmp imm: bad size".into())),
    })
}
fn shift_imm_code(size: u32, logical: bool) -> Result<Code, AsmError> {
    Ok(match (size, logical) {
        (64, false) => Code::Shl_rm64_imm8, (64, true) => Code::Shr_rm64_imm8,
        (32, false) => Code::Shl_rm32_imm8, (32, true) => Code::Shr_rm32_imm8,
        (16, false) => Code::Shl_rm16_imm8, (16, true) => Code::Shr_rm16_imm8,
        (8, false) => Code::Shl_rm8_imm8, (8, true) => Code::Shr_rm8_imm8,
        _ => return Err(AsmError::Encode("shift: bad size".into())),
    })
}
fn shift_cl_code(size: u32, logical: bool) -> Result<Code, AsmError> {
    Ok(match (size, logical) {
        (64, false) => Code::Shl_rm64_CL, (64, true) => Code::Shr_rm64_CL,
        (32, false) => Code::Shl_rm32_CL, (32, true) => Code::Shr_rm32_CL,
        _ => return Err(AsmError::Encode("shift cl: 8/16-bit forms go through imm for MVP".into())),
    })
}
fn unary_code(u: Unary, size: u32) -> Result<Code, AsmError> {
    Ok(match (u, size) {
        (Unary::Neg, 64) => Code::Neg_rm64, (Unary::Neg, 32) => Code::Neg_rm32,
        (Unary::Neg, 16) => Code::Neg_rm16, (Unary::Neg, 8) => Code::Neg_rm8,
        (Unary::Not, 64) => Code::Not_rm64, (Unary::Not, 32) => Code::Not_rm32,
        (Unary::Not, 16) => Code::Not_rm16, (Unary::Not, 8) => Code::Not_rm8,
        (Unary::Inc, 64) => Code::Inc_rm64, (Unary::Inc, 32) => Code::Inc_rm32,
        (Unary::Inc, 16) => Code::Inc_rm16, (Unary::Inc, 8) => Code::Inc_rm8,
        (Unary::Dec, 64) => Code::Dec_rm64, (Unary::Dec, 32) => Code::Dec_rm32,
        (Unary::Dec, 16) => Code::Dec_rm16, (Unary::Dec, 8) => Code::Dec_rm8,
        _ => return Err(AsmError::Encode("unary: bad size".into())),
    })
}
fn mul_code(size: u32) -> Result<Code, AsmError> {
    Ok(match size {
        64 => Code::Mul_rm64, 32 => Code::Mul_rm32,
        16 => Code::Mul_rm16, 8 => Code::Mul_rm8,
        _ => return Err(AsmError::Encode("mul: bad size".into())),
    })
}
fn imul_wide(size: u32) -> Result<Code, AsmError> {
    Ok(match size {
        64 => Code::Imul_rm64, 32 => Code::Imul_rm32,
        16 => Code::Imul_rm16, 8 => Code::Imul_rm8,
        _ => return Err(AsmError::Encode("imul wide: bad size".into())),
    })
}
fn div_code(size: u32) -> Result<Code, AsmError> {
    Ok(match size {
        64 => Code::Div_rm64, 32 => Code::Div_rm32,
        16 => Code::Div_rm16, 8 => Code::Div_rm8,
        _ => return Err(AsmError::Encode("div: bad size".into())),
    })
}
fn idiv_code(size: u32) -> Result<Code, AsmError> {
    Ok(match size {
        64 => Code::Idiv_rm64, 32 => Code::Idiv_rm32,
        16 => Code::Idiv_rm16, 8 => Code::Idiv_rm8,
        _ => return Err(AsmError::Encode("idiv: bad size".into())),
    })
}
fn xchg_code(size: u32) -> Result<Code, AsmError> {
    Ok(match size {
        64 => Code::Xchg_rm64_r64, 32 => Code::Xchg_rm32_r32,
        16 => Code::Xchg_rm16_r16, 8 => Code::Xchg_rm8_r8,
        _ => return Err(AsmError::Encode("xchg: bad size".into())),
    })
}
fn push_r(size: u32) -> Code {
    match size { 64 => Code::Push_r64, _ => Code::Push_r16 }
}
fn push_rm(size: u32) -> Code {
    match size { 64 => Code::Push_rm64, _ => Code::Push_rm16 }
}
fn push_imm(size: u32) -> Code {
    match size { 64 => Code::Pushq_imm32, _ => Code::Push_imm16 }
}
fn pop_r(size: u32) -> Code {
    match size { 64 => Code::Pop_r64, _ => Code::Pop_r16 }
}
fn pop_rm(size: u32) -> Code {
    match size { 64 => Code::Pop_rm64, _ => Code::Pop_rm16 }
}
fn movzx_code(dst: u32, src: u32) -> Result<Code, AsmError> {
    Ok(match (dst, src) {
        (64, 8) => Code::Movzx_r64_rm8, (64, 16) => Code::Movzx_r64_rm16,
        (32, 8) => Code::Movzx_r32_rm8, (32, 16) => Code::Movzx_r32_rm16,
        _ => return Err(AsmError::Encode("movzx: unsupported widths".into())),
    })
}
fn movsx_code(dst: u32, src: u32) -> Result<Code, AsmError> {
    Ok(match (dst, src) {
        (64, 8) => Code::Movsx_r64_rm8, (64, 16) => Code::Movsx_r64_rm16,
        (64, 32) => Code::Movsxd_r64_rm32,
        (32, 8) => Code::Movsx_r32_rm8, (32, 16) => Code::Movsx_r32_rm16,
        _ => return Err(AsmError::Encode("movsx: unsupported widths".into())),
    })
}
fn jcc_code(cc: Jcc) -> Code {
    match cc {
        Jcc::E => Code::Je_rel32_64, Jcc::Ne => Code::Jne_rel32_64,
        Jcc::L => Code::Jl_rel32_64, Jcc::Le => Code::Jle_rel32_64,
        Jcc::G => Code::Jg_rel32_64, Jcc::Ge => Code::Jge_rel32_64,
        Jcc::B => Code::Jb_rel32_64, Jcc::Be => Code::Jbe_rel32_64,
        Jcc::A => Code::Ja_rel32_64, Jcc::Ae => Code::Jae_rel32_64,
        Jcc::S => Code::Js_rel32_64, Jcc::Ns => Code::Jns_rel32_64,
        Jcc::O => Code::Jo_rel32_64, Jcc::No => Code::Jno_rel32_64,
        Jcc::P => Code::Jp_rel32_64, Jcc::Np => Code::Jnp_rel32_64,
    }
}

// ---------------------------------------------------------------------------
// register conversion
// ---------------------------------------------------------------------------

pub fn to_iced_reg(r: Reg) -> Result<Register, AsmError> {
    match r {
        Reg::Rip => Ok(Register::RIP),
        Reg::GprHigh8(b) => Ok(match b {
            GprBase::A => Register::AH, GprBase::B => Register::BH,
            GprBase::C => Register::CH, GprBase::D => Register::DH,
            _ => return Err(AsmError::Encode("high8 form only exists for a/b/c/d".into())),
        }),
        Reg::Xmm(n) => Ok(XMM[n as usize]),
        Reg::Gpr { base, size } => Ok(gpr_to_iced(base, size)),
    }
}

const XMM: [Register; 16] = [
    Register::XMM0, Register::XMM1, Register::XMM2, Register::XMM3,
    Register::XMM4, Register::XMM5, Register::XMM6, Register::XMM7,
    Register::XMM8, Register::XMM9, Register::XMM10, Register::XMM11,
    Register::XMM12, Register::XMM13, Register::XMM14, Register::XMM15,
];

fn gpr_to_iced(b: GprBase, size: RegSize) -> Register {
    // enc_id: A=0 C=1 D=2 B=3 Sp=4 Bp=5 Si=6 Di=7 — matches the tables below
    let idx = b.enc_id() as usize;
    match size {
        RegSize::R64 => R64[idx],
        RegSize::R32 => R32[idx],
        RegSize::R16 => R16[idx],
        RegSize::R8 => R8[idx],
    }
}

const R64: [Register; 16] = [
    Register::RAX, Register::RCX, Register::RDX, Register::RBX,
    Register::RSP, Register::RBP, Register::RSI, Register::RDI,
    Register::R8, Register::R9, Register::R10, Register::R11,
    Register::R12, Register::R13, Register::R14, Register::R15,
];
const R32: [Register; 16] = [
    Register::EAX, Register::ECX, Register::EDX, Register::EBX,
    Register::ESP, Register::EBP, Register::ESI, Register::EDI,
    Register::R8D, Register::R9D, Register::R10D, Register::R11D,
    Register::R12D, Register::R13D, Register::R14D, Register::R15D,
];
const R16: [Register; 16] = [
    Register::AX, Register::CX, Register::DX, Register::BX,
    Register::SP, Register::BP, Register::SI, Register::DI,
    Register::R8W, Register::R9W, Register::R10W, Register::R11W,
    Register::R12W, Register::R13W, Register::R14W, Register::R15W,
];
const R8: [Register; 16] = [
    Register::AL, Register::CL, Register::DL, Register::BL,
    Register::SPL, Register::BPL, Register::SIL, Register::DIL,
    Register::R8L, Register::R9L, Register::R10L, Register::R11L,
    Register::R12L, Register::R13L, Register::R14L, Register::R15L,
];

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Section payloads (rodata/data) and .bss size.
pub fn section_bytes(sec: &SectionData) -> (Vec<u8>, u64) {
    let mut bytes = Vec::new();
    let mut size = 0u64;
    for item in &sec.items {
        match item {
            DataItem::Bytes { offset, bytes: b, .. } => {
                if *offset as usize > bytes.len() {
                    bytes.resize(*offset as usize, 0);
                }
                bytes.extend_from_slice(b);
                size = size.max(*offset + b.len() as u64);
            }
            DataItem::Zero { offset, size: s, .. } => {
                size = size.max(*offset + *s);
            }
        }
    }
    (bytes, size)
}

/// Disassemble bytes (test oracle + `--expand`-style dumps).
pub fn disassemble(bytes: &[u8], ip: u64) -> Vec<String> {
    let mut dec = Decoder::new(64, bytes, DecoderOptions::NONE);
    dec.set_ip(ip);
    let mut fmt = FastFormatter::new();
    let mut out = Vec::new();
    for i in dec {
        let mut s = String::new();
        fmt.format(&i, &mut s);
        out.push(format!("{:08x}  {}", i.ip(), s));
    }
    out
}
