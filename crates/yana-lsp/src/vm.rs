//! A tiny interpreter for the YANA IR — the execution engine behind the DAP
//! adapter (`yana-lsp --dap`).
//!
//! YANA compiles to a small, explicit instruction set (§0), so a debugger can
//! run the IR directly without any DWARF/ELF debug info: every [`Insn`] carries
//! its source span, which gives us breakpoints and stack traces for free.
//!
//! The model is intentionally simple and safe:
//! - 16 GPRs as `u64` (32-bit writes zero-extend, 8/16-bit writes preserve),
//! - a flat little-endian 4 MiB address space with static data mapped in,
//! - a descending stack, `call`/`ret` tracked both in memory and in frames,
//! - Linux syscalls emulated minimally (`write`, `exit`, …).
//!
//! It is not a cycle-accurate x86-64 emulator; it runs exactly the IR that
//! `yana build`/`yana run` would encode.

use std::collections::HashSet;
use std::path::PathBuf;

use yana_ast::diag::SourceMap;
use yana_ast::place::SectionKind;
use yana_ast::reg::Reg;
use yana_codegen::ir::{
    AtomicOp, DataItem, Displacement, Insn, Jcc, MemOp, Module, Operand, SymbolKind, WideOp,
};

/// Total emulated address space (bytes).
pub const MEM_SIZE: usize = 4 * 1024 * 1024;
/// Stack grows down from here (top of the address space).
const STACK_TOP: u64 = MEM_SIZE as u64;

// `GprBase::A.enc_id()` == 0, `Sp` == 4, `Di` == 7.
const RAX: usize = 0;
const RDX: usize = 2;
const RSI: usize = 6;
const RDI: usize = 7;
const RSP: usize = 4; // rsp: `GprBase::Sp.enc_id()` §3

#[derive(Debug, Clone, Copy, Default)]
pub struct Flags {
    pub cf: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
    pub pf: bool,
}

/// One pending return address: where execution resumes after `ret`.
#[derive(Debug, Clone)]
pub struct CallSite {
    pub body: usize,
    pub pc: usize,
    pub name: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Continue,
    StepIn,
    StepOver,
    StepOut,
}

#[derive(Debug)]
pub enum RunOutcome {
    /// Execution paused at `self.body`/`self.pc`.
    Stopped(String),
    /// Program exited with this status.
    Exited(i32),
    /// The interpreter hit something it cannot run.
    Fault(String),
}

enum Exec {
    Continue,
    Exit(i32),
    Fault(String),
}

pub struct Vm {
    pub module: Module,
    pub source: String,
    pub path: PathBuf,
    pub map: SourceMap,

    /// GPR file indexed by [`GprBase::enc_id`].
    pub regs: [u64; 16],
    pub flags: Flags,
    pub mem: Vec<u8>,

    /// Currently executing function body (index into `module.bodies`).
    pub body: usize,
    /// Next instruction to execute (index into `body.insns`).
    pub pc: usize,
    pub frames: Vec<CallSite>,

    /// Body of `#[entry]` — codegen renames it to `_start`, so keep the
    /// source-level name for stack traces.
    pub entry_body: usize,
    pub entry_name: Option<String>,

    /// Bytes captured from `write(2)`.
    pub output: Vec<u8>,
    /// Set once the program exits.
    pub exit: Option<i32>,
    pub steps: u64,
}

impl Vm {
    pub fn new(module: Module, source: String, path: PathBuf) -> Result<Self, String> {
        let map = SourceMap::new(&source);
        let mut mem = vec![0u8; MEM_SIZE];

        // Map static data into the address space.
        for sec in &module.sections {
            let base = section_base(sec.kind);
            for item in &sec.items {
                if let DataItem::Bytes { offset, bytes, .. } = item {
                    let start = (base + *offset) as usize;
                    if start >= MEM_SIZE {
                        continue;
                    }
                    let end = (start + bytes.len()).min(MEM_SIZE);
                    mem[start..end].copy_from_slice(&bytes[..end - start]);
                }
            }
        }

        let body = entry_body(&module)
            .ok_or_else(|| "no function body to run (missing #[entry]?)".to_string())?;

        let mut regs = [0u64; 16];
        // Entry behaves as if `call`ed: return address occupies the top slot.
        regs[RSP] = STACK_TOP - 8;

        let entry_name = source_entry_name(&source);

        Ok(Vm {
            module,
            source,
            path,
            map,
            regs,
            flags: Flags::default(),
            mem,
            body,
            pc: 0,
            frames: Vec::new(),
            entry_body: body,
            entry_name,
            output: Vec::new(),
            exit: None,
            steps: 0,
        })
    }

    // ------------------------------------------------------------------
    // Queries used by the DAP layer
    // ------------------------------------------------------------------

    pub fn body_name(&self, body: usize) -> String {
        if body == self.entry_body {
            if let Some(name) = &self.entry_name {
                return name.clone();
            }
        }
        self.module
            .bodies
            .get(body)
            .and_then(|b| self.module.symbols.get(b.symbol))
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "<unknown>".to_string())
    }

    pub fn fn_name_at(&self) -> String {
        self.body_name(self.body)
    }

    /// 1-based line/column of the instruction at `(body, pc)`.
    pub fn line_col_at(&self, body: usize, pc: usize) -> (u32, u32) {
        let Some(fb) = self.module.bodies.get(body) else {
            return (1, 1);
        };
        if fb.insns.is_empty() {
            return (1, 1);
        }
        let i = pc.min(fb.insns.len() - 1);
        let (line, col) = self.map.offset_to_line_col(fb.insns[i].span.lo);
        (line + 1, col + 1)
    }

    /// 1-based line of the next instruction (or `None` at the end of a body).
    pub fn current_line(&self) -> Option<u32> {
        let fb = self.module.bodies.get(self.body)?;
        let insn = fb.insns.get(self.pc).or_else(|| fb.insns.last())?;
        Some(self.map.offset_to_line_col(insn.span.lo).0 + 1)
    }

    /// Is there at least one instruction generated from `line` (1-based)?
    pub fn has_line(&self, line: u32) -> bool {
        self.module.bodies.iter().any(|b| {
            b.insns
                .iter()
                .any(|i| self.map.offset_to_line_col(i.span.lo).0 + 1 == line)
        })
    }

    pub fn is_running(&self) -> bool {
        self.exit.is_none()
    }

    // Public accessors for the DAP layer (registers / stack views).

    pub fn get_reg(&self, r: Reg) -> u64 {
        self.read_reg(r, 64)
    }

    pub fn set_reg(&mut self, r: Reg, v: u64) {
        self.write_reg(r, 64, v);
    }

    pub fn peek(&self, addr: u64) -> u64 {
        self.read_mem(addr, 64)
    }

    pub fn rsp(&self) -> u64 {
        self.regs[RSP]
    }

    /// Symbol address in the emulated address space.
    pub fn sym_addr(&self, sym: usize) -> Option<u64> {
        match self.module.symbols.get(sym).map(|s| &s.kind) {
            Some(SymbolKind::Static { section, offset, .. }) => Some(section_base(*section) + *offset),
            Some(SymbolKind::ExternStatic { .. }) => Some(0),
            _ => None,
        }
    }

    // ------------------------------------------------------------------
    // Execution
    // ------------------------------------------------------------------

    pub fn run(&mut self, mode: RunMode, breakpoints: &HashSet<u32>) -> RunOutcome {
        let start_depth = self.frames.len();
        let start_line = self.current_line();
        let mut executed: u64 = 0;

        loop {
            if let Some(code) = self.exit {
                return RunOutcome::Exited(code);
            }
            if executed > 20_000_000 {
                return RunOutcome::Fault("instruction limit reached (infinite loop?)".into());
            }

            if self.pc >= self.body_len() {
                // Implicit `ret` at the end of a function.
                match self.do_ret() {
                    Some(code) => return RunOutcome::Exited(code),
                    None => {}
                }
            } else {
                match self.exec_one() {
                    Exec::Continue => {}
                    Exec::Exit(code) => return RunOutcome::Exited(code),
                    Exec::Fault(msg) => return RunOutcome::Fault(msg),
                }
                executed += 1;
                self.steps += 1;
            }

            if let Some(code) = self.exit {
                return RunOutcome::Exited(code);
            }

            let line = self.current_line();

            match mode {
                RunMode::StepIn => {
                    if line != start_line {
                        return RunOutcome::Stopped("step".into());
                    }
                }
                RunMode::StepOver => {
                    if self.frames.len() <= start_depth && line != start_line {
                        return RunOutcome::Stopped("step".into());
                    }
                }
                RunMode::StepOut => {
                    if self.frames.len() < start_depth {
                        return RunOutcome::Stopped("step".into());
                    }
                }
                RunMode::Continue => {}
            }

            if let Some(l) = line {
                if breakpoints.contains(&l) && Some(l) != start_line {
                    return RunOutcome::Stopped("breakpoint".into());
                }
            }
        }
    }

    fn body_len(&self) -> usize {
        self.module.bodies.get(self.body).map(|b| b.insns.len()).unwrap_or(0)
    }

    fn exec_one(&mut self) -> Exec {
        let insn = match self.module.bodies.get(self.body).and_then(|b| b.insns.get(self.pc)) {
            Some(s) => s.insn.clone(),
            None => return Exec::Continue,
        };
        let here = self.pc;
        self.pc += 1;
        self.exec_insn(&insn, here)
    }

    fn do_ret(&mut self) -> Option<i32> {
        // Pop the emulated return slot.
        let rsp = self.regs[RSP].wrapping_add(8);
        self.regs[RSP] = rsp;

        if let Some(cs) = self.frames.pop() {
            self.body = cs.body;
            self.pc = cs.pc;
            None
        } else {
            let code = self.regs[RAX] as i32;
            self.exit = Some(code);
            Some(code)
        }
    }

    fn exec_insn(&mut self, insn: &Insn, here: usize) -> Exec {
        match insn {
            Insn::Nop => {}

            Insn::Volatile(inner) => return self.exec_insn(inner, here),

            Insn::Mov { dst, src, size } => {
                let v = self.read_op(src, *size);
                self.write_op(dst, *size, v);
            }

            Insn::Movzx { dst, src, src_size, dst_size } => {
                let v = self.read_op(src, *src_size) & mask(*src_size);
                self.write_reg(*dst, *dst_size, v);
            }

            Insn::Movsx { dst, src, src_size, dst_size } => {
                let v = sign_extend(self.read_op(src, *src_size), *src_size);
                self.write_reg(*dst, *dst_size, v);
            }

            Insn::Lea { dst, addr } => {
                let a = self.ea(addr);
                self.write_reg(*dst, 64, a);
            }

            Insn::LeaSym { dst, sym, add } => {
                let a = self.sym_addr(*sym).unwrap_or(0).wrapping_add(*add as u64);
                self.write_reg(*dst, 64, a);
            }

            Insn::Push { src, size } => {
                let v = self.read_op(src, *size);
                let rsp = self.regs[RSP].wrapping_sub(8);
                self.regs[RSP] = rsp;
                self.write_mem(rsp, 64, v);
            }

            Insn::Pop { dst, size } => {
                let rsp = self.regs[RSP];
                let v = self.read_mem(rsp, *size);
                self.regs[RSP] = rsp.wrapping_add(8);
                self.write_op(dst, *size, v);
            }

            Insn::StackSlot { grow } => {
                let rsp = self.regs[RSP];
                self.regs[RSP] = if *grow { rsp.wrapping_sub(8) } else { rsp.wrapping_add(8) };
            }

            Insn::StackAlign { align } => {
                self.regs[RSP] = self.regs[RSP].wrapping_sub(*align as u64);
            }

            Insn::StackPad { pad } => {
                self.regs[RSP] = self.regs[RSP].wrapping_sub(*pad as u64);
            }

            Insn::Xchg { a, b, size } => {
                let va = self.read_op(a, *size);
                let vb = self.read_op(b, *size);
                self.write_op(a, *size, vb);
                self.write_op(b, *size, va);
            }

            Insn::Add { dst, src, size } => {
                let a = self.read_op(dst, *size);
                let b = self.read_op(src, *size);
                let r = a.wrapping_add(b) & mask(*size);
                self.set_add_flags(a, b, r, *size);
                self.write_op(dst, *size, r);
            }

            Insn::Sub { dst, src, size } => {
                let a = self.read_op(dst, *size);
                let b = self.read_op(src, *size);
                let r = a.wrapping_sub(b) & mask(*size);
                self.set_sub_flags(a, b, r, *size);
                self.write_op(dst, *size, r);
            }

            Insn::And { dst, src, size } => {
                let r = self.read_op(dst, *size) & self.read_op(src, *size);
                self.set_logic_flags(r, *size);
                self.write_op(dst, *size, r);
            }

            Insn::Or { dst, src, size } => {
                let r = self.read_op(dst, *size) | self.read_op(src, *size);
                self.set_logic_flags(r, *size);
                self.write_op(dst, *size, r);
            }

            Insn::Xor { dst, src, size } => {
                let r = self.read_op(dst, *size) ^ self.read_op(src, *size);
                self.set_logic_flags(r, *size);
                self.write_op(dst, *size, r);
            }

            Insn::Shl { dst, src, size } => {
                let a = self.read_op(dst, *size);
                let sh = self.read_op(src, *size) & (size_bits(*size) as u64 - 1);
                let r = a.wrapping_shl(sh as u32) & mask(*size);
                self.set_logic_flags(r, *size);
                self.write_op(dst, *size, r);
            }

            Insn::Shr { dst, src, size } => {
                let a = self.read_op(dst, *size);
                let sh = self.read_op(src, *size) & (size_bits(*size) as u64 - 1);
                let r = a.wrapping_shr(sh as u32) & mask(*size);
                self.set_logic_flags(r, *size);
                self.write_op(dst, *size, r);
            }

            Insn::Imul2 { dst, src, size } => {
                let a = self.read_op(dst, *size);
                let b = self.read_op(src, *size);
                let r = a.wrapping_mul(b) & mask(*size);
                self.set_logic_flags(r, *size);
                self.write_op(dst, *size, r);
            }

            Insn::Neg { dst, size } => {
                let a = self.read_op(dst, *size);
                let r = (0u64).wrapping_sub(a) & mask(*size);
                self.set_sub_flags(0, a, r, *size);
                self.write_op(dst, *size, r);
            }

            Insn::Not { dst, size } => {
                let r = !self.read_op(dst, *size) & mask(*size);
                self.write_op(dst, *size, r);
            }

            Insn::Inc { dst, size } => {
                let a = self.read_op(dst, *size);
                let r = a.wrapping_add(1) & mask(*size);
                self.set_add_flags(a, 1, r, *size);
                self.write_op(dst, *size, r);
            }

            Insn::Dec { dst, size } => {
                let a = self.read_op(dst, *size);
                let r = a.wrapping_sub(1) & mask(*size);
                self.set_sub_flags(a, 1, r, *size);
                self.write_op(dst, *size, r);
            }

            Insn::Cmp { a, b, size } => {
                let va = self.read_op(a, *size);
                let vb = self.read_op(b, *size);
                let r = va.wrapping_sub(vb) & mask(*size);
                self.set_sub_flags(va, vb, r, *size);
            }

            Insn::MulWide { src, signed, size } => {
                let b = self.read_op(src, *size);
                if *signed {
                    let a = sign_extend(self.regs[RAX], *size) as i64 as i128;
                    let bb = sign_extend(b, *size) as i64 as i128;
                    let p = a * bb;
                    self.regs[RAX] = p as u64;
                    self.regs[RDX] = (p >> 64) as u64;
                } else {
                    let a = (self.regs[RAX] & mask(*size)) as u128;
                    let bb = (b & mask(*size)) as u128;
                    let p = a * bb;
                    self.regs[RAX] = p as u64;
                    self.regs[RDX] = (p >> 64) as u64;
                }
                self.set_logic_flags(self.regs[RAX], *size);
            }

            Insn::DivWide { src, op, size } => {
                let b = self.read_op(src, *size);
                if b == 0 {
                    return Exec::Fault("division by zero".into());
                }
                let bits = size_bits(*size) as u32;
                let wide = ((self.regs[RDX] as u128) << bits) | (self.regs[RAX] as u128 & mask128(*size));
                if *op == WideOp::Unsigned {
                    let q = wide / (b as u128);
                    let r = wide % (b as u128);
                    self.regs[RAX] = q as u64;
                    self.regs[RDX] = r as u64;
                } else {
                    let sign = 1u128 << (bits * 2 - 1);
                    let signed = if wide & sign != 0 { (wide as i128) - (1i128 << (bits * 2)) } else { wide as i128 };
                    let divisor = sign_extend(b, *size) as i64 as i128;
                    if divisor == 0 {
                        return Exec::Fault("division by zero".into());
                    }
                    let q = signed / divisor;
                    let r = signed % divisor;
                    self.regs[RAX] = q as u64;
                    self.regs[RDX] = r as u64;
                }
            }

            Insn::ExtendPair { signed, size } => {
                if *signed {
                    self.regs[RDX] = if (self.regs[RAX] & (1 << (size_bits(*size) - 1))) != 0 { u64::MAX } else { 0 };
                } else {
                    self.regs[RDX] = 0;
                }
            }

            Insn::Jmp { label } => {
                if let Some(target) = self.label_target(*label) {
                    self.pc = target;
                }
            }

            Insn::Jcc { cc, label } => {
                if self.cond(*cc) {
                    if let Some(target) = self.label_target(*label) {
                        self.pc = target;
                    }
                }
            }

            Insn::Call { sym, contract } => {
                if let Some(nr) = contract.syscall {
                    self.syscall(nr);
                    return Exec::Continue;
                }
                let target = match self.module.symbols.get(*sym).map(|s| &s.kind) {
                    Some(SymbolKind::Function { body_index }) => Some(*body_index),
                    _ => None,
                };
                match target {
                    Some(bi) => {
                        // Push the emulated return address.
                        let rsp = self.regs[RSP].wrapping_sub(8);
                        self.regs[RSP] = rsp;
                        self.write_mem(rsp, 64, 0);

                        let (line, column) = self.line_col_at(self.body, here);
                        let name = self.body_name(self.body);
                        self.frames.push(CallSite { body: self.body, pc: self.pc, name, line, column });
                        self.body = bi;
                        self.pc = 0;
                    }
                    None => {
                        // Unknown/extern call: model as returning 0.
                        self.regs[RAX] = 0;
                    }
                }
            }

            Insn::Syscall => {
                let nr = self.regs[RAX] as i64;
                self.syscall(nr);
            }

            Insn::Ret => {
                if let Some(code) = self.do_ret() {
                    return Exec::Exit(code);
                }
            }

            Insn::Int3 => {
                return Exec::Fault("int3 trap (§13: reached unreachable code)".into());
            }

            Insn::Ud2 => {
                return Exec::Fault("ud2 trap (§13: reached unreachable code)".into());
            }

            Insn::AtomicRMW { op, dst, src, size, .. } => {
                let addr = self.ea_operand(dst);
                let cur = self.read_mem(addr, *size);
                let v = self.read_op(src, *size);
                let new = match op {
                    AtomicOp::Exchange => v,
                    AtomicOp::Add => cur.wrapping_add(v),
                    AtomicOp::Sub => cur.wrapping_sub(v),
                    AtomicOp::And => cur & v,
                    AtomicOp::Or => cur | v,
                    AtomicOp::Xor => cur ^ v,
                } & mask(*size);
                self.write_mem(addr, *size, new);
                // `xchg` writes the old value back into the source register.
                if *op == AtomicOp::Exchange {
                    self.write_op(src, *size, cur);
                }
            }
        }

        Exec::Continue
    }

    fn label_target(&self, label: usize) -> Option<usize> {
        self.module
            .bodies
            .get(self.body)
            .and_then(|b| b.label_defs.get(label))
            .map(|l| l.at_insn)
    }

    fn syscall(&mut self, nr: i64) {
        match nr {
            // read
            0 => {
                self.regs[RAX] = 0;
            }
            // write / writev (treat writev as write for the common fd=1 case)
            1 | 2 => {
                let len = self.regs[RDX];
                let addr = self.regs[RSI] as usize;
                let end = (addr as u64 + len).min(MEM_SIZE as u64) as usize;
                if addr < MEM_SIZE {
                    let bytes = self.mem[addr..end].to_vec();
                    self.output.extend_from_slice(&bytes);
                    self.regs[RAX] = (end - addr) as u64;
                } else {
                    self.regs[RAX] = (-14i64) as u64; // EFAULT
                }
            }
            // exit / exit_group
            60 | 231 => {
                self.exit = Some(self.regs[RDI] as i32);
            }
            // brk / mmap: pretend success, return a scratch pointer
            12 => self.regs[RAX] = 0x1000,
            9 => self.regs[RAX] = 0x1000,
            // anything else: ENOSYS
            _ => {
                self.regs[RAX] = (-38i64) as u64;
            }
        }
    }

    // ------------------------------------------------------------------
    // Operand / memory helpers
    // ------------------------------------------------------------------

    fn read_op(&self, op: &Operand, size: u32) -> u64 {
        match op {
            Operand::Reg(r) => self.read_reg(*r, size),
            Operand::Imm(v) => (*v as u64) & mask(size),
            Operand::Mem(m) => {
                let a = self.ea(m);
                self.read_mem(a, size)
            }
            Operand::Sym { sym, add } => {
                self.sym_addr(*sym).unwrap_or(0).wrapping_add(*add as u64)
            }
        }
    }

    fn write_op(&mut self, op: &Operand, size: u32, val: u64) {
        match op {
            Operand::Reg(r) => self.write_reg(*r, size, val),
            Operand::Imm(_) => {}
            Operand::Mem(m) => {
                let a = self.ea(m);
                self.write_mem(a, size, val);
            }
            Operand::Sym { .. } => {}
        }
    }

    fn ea_operand(&self, op: &Operand) -> u64 {
        match op {
            Operand::Mem(m) => self.ea(m),
            Operand::Sym { sym, add } => self.sym_addr(*sym).unwrap_or(0).wrapping_add(*add as u64),
            Operand::Reg(r) => self.read_reg(*r, 64),
            Operand::Imm(v) => *v as u64,
        }
    }

    fn ea(&self, m: &MemOp) -> u64 {
        let mut a = 0u64;
        if let Some(base) = m.base {
            a = a.wrapping_add(self.read_reg(base, 64));
        }
        if let Some(index) = m.index {
            a = a.wrapping_add(self.read_reg(index, 64).wrapping_mul(m.scale as u64));
        }
        a = a.wrapping_add(match &m.disp {
            Displacement::Const(v) => *v as u64,
            Displacement::Sym { sym, add } => {
                self.sym_addr(*sym).unwrap_or(0).wrapping_add(*add as u64)
            }
        });
        a
    }

    fn read_reg(&self, r: Reg, size: u32) -> u64 {
        let bits = size_bits(size);
        match r {
            Reg::Gpr { base, .. } => self.regs[base.enc_id() as usize] & mask(bits),
            Reg::GprHigh8(base) => (self.regs[base.enc_id() as usize] >> 8) & 0xff,
            Reg::Rip => 0,
            Reg::Xmm(_) => 0,
        }
    }

    fn write_reg(&mut self, r: Reg, size: u32, val: u64) {
        let bits = size_bits(size);
        match r {
            Reg::Gpr { base, .. } => {
                let i = base.enc_id() as usize;
                match bits {
                    8 => self.regs[i] = (self.regs[i] & !0xff) | (val & 0xff),
                    16 => self.regs[i] = (self.regs[i] & !0xffff) | (val & 0xffff),
                    // 32-bit writes zero-extend into the 64-bit register.
                    32 => self.regs[i] = val & 0xffff_ffff,
                    _ => self.regs[i] = val,
                }
            }
            Reg::GprHigh8(base) => {
                let i = base.enc_id() as usize;
                self.regs[i] = (self.regs[i] & !0xff00) | ((val & 0xff) << 8);
            }
            Reg::Rip | Reg::Xmm(_) => {}
        }
    }

    fn read_mem(&self, addr: u64, size: u32) -> u64 {
        let n = (size_bits(size) / 8) as usize;
        let start = addr as usize;
        if start + n > MEM_SIZE {
            return 0;
        }
        let mut v = 0u64;
        for i in 0..n.min(8) {
            v |= (self.mem[start + i] as u64) << (i * 8);
        }
        v
    }

    fn write_mem(&mut self, addr: u64, size: u32, val: u64) {
        let n = (size_bits(size) / 8) as usize;
        let start = addr as usize;
        if start + n > MEM_SIZE {
            return;
        }
        for i in 0..n.min(8) {
            self.mem[start + i] = ((val >> (i * 8)) & 0xff) as u8;
        }
    }

    // ------------------------------------------------------------------
    // Flags
    // ------------------------------------------------------------------

    fn cond(&self, cc: Jcc) -> bool {
        match cc {
            Jcc::E => self.flags.zf,
            Jcc::Ne => !self.flags.zf,
            Jcc::L => self.flags.sf != self.flags.of,
            Jcc::Le => self.flags.zf || self.flags.sf != self.flags.of,
            Jcc::G => !self.flags.zf && self.flags.sf == self.flags.of,
            Jcc::Ge => self.flags.sf == self.flags.of,
            Jcc::B => self.flags.cf,
            Jcc::Be => self.flags.cf || self.flags.zf,
            Jcc::A => !self.flags.cf && !self.flags.zf,
            Jcc::Ae => !self.flags.cf,
            Jcc::S => self.flags.sf,
            Jcc::Ns => !self.flags.sf,
            Jcc::O => self.flags.of,
            Jcc::No => !self.flags.of,
            Jcc::P => self.flags.pf,
            Jcc::Np => !self.flags.pf,
        }
    }

    fn set_logic_flags(&mut self, res: u64, size: u32) {
        let bits = size_bits(size);
        self.flags.zf = res & mask(bits) == 0;
        self.flags.sf = (res & (1 << (bits - 1))) != 0;
        self.flags.cf = false;
        self.flags.of = false;
        self.flags.pf = (res & 0xff).count_ones() % 2 == 0;
    }

    fn set_add_flags(&mut self, a: u64, b: u64, res: u64, size: u32) {
        let bits = size_bits(size);
        let m = mask(bits);
        let sign = 1u64 << (bits - 1);
        self.flags.cf = ((a & m) as u128 + (b & m) as u128) > m as u128;
        self.flags.zf = res & m == 0;
        self.flags.sf = (res & sign) != 0;
        self.flags.of = ((a ^ res) & (b ^ res) & sign) != 0;
        self.flags.pf = (res & 0xff).count_ones() % 2 == 0;
    }

    fn set_sub_flags(&mut self, a: u64, b: u64, res: u64, size: u32) {
        let bits = size_bits(size);
        let m = mask(bits);
        let sign = 1u64 << (bits - 1);
        self.flags.cf = (a & m) < (b & m);
        self.flags.zf = res & m == 0;
        self.flags.sf = (res & sign) != 0;
        self.flags.of = ((a ^ b) & (a ^ res) & sign) != 0;
        self.flags.pf = (res & 0xff).count_ones() % 2 == 0;
    }
}

fn entry_body(module: &Module) -> Option<usize> {
    let from_sym = |sym: usize| match module.symbols.get(sym).map(|s| &s.kind) {
        Some(SymbolKind::Function { body_index }) => Some(*body_index),
        _ => None,
    };
    module
        .entry
        .and_then(from_sym)
        .or_else(|| module.bodies.first().map(|b| b.symbol).and_then(from_sym))
        .or_else(|| (!module.bodies.is_empty()).then_some(0))
}

/// Find the source-level name of the `#[entry]` function (the first `fn NAME`
/// after an `#[entry]` attribute). Codegen exports it as `_start`, but a
/// debugger should show the name the user wrote.
fn source_entry_name(source: &str) -> Option<String> {
    let mut saw_entry = false;
    for line in source.lines() {
        if line.contains("#[entry]") {
            saw_entry = true;
        }
        if !saw_entry {
            continue;
        }
        if let Some(pos) = line.find("fn ") {
            let rest = &line[pos + 3..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

fn section_base(kind: SectionKind) -> u64 {
    match kind {
        SectionKind::Text => 0x1000,
        SectionKind::RoData => 0x100_000,
        SectionKind::Data => 0x200_000,
        SectionKind::Bss => 0x300_000,
    }
}

fn size_bits(size: u32) -> u32 {
    match size {
        8 | 16 | 32 | 64 => size,
        _ => 64,
    }
}

fn mask(size: u32) -> u64 {
    match size_bits(size) {
        64 => u64::MAX,
        b => (1u64 << b) - 1,
    }
}

fn mask128(size: u32) -> u128 {
    match size_bits(size) {
        64 => u64::MAX as u128,
        b => (1u128 << b) - 1,
    }
}

fn sign_extend(v: u64, size: u32) -> u64 {
    let bits = size_bits(size);
    if bits >= 64 {
        return v;
    }
    let shift = 64 - bits;
    (((v << shift) as i64) >> shift) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(src: &str) -> (Vm, yana_ast::diag::SourceMap) {
        let parsed = yana_parser::parse(src);
        assert!(!parsed.has_errors(), "parse errors: {:?}", parsed.diagnostics);
        let file = parsed.file.expect("file");
        let out = yana_codegen::resolve_module(
            &file,
            &yana_codegen::TargetInfo::linux_x86_64(),
            &yana_codegen::ResolveOptions::default(),
        );
        assert!(!out.has_errors(), "resolve errors: {:?}", out.diagnostics);
        let map = yana_ast::diag::SourceMap::new(src);
        let vm = Vm::new(out.module, src.to_string(), PathBuf::from("test.yana")).unwrap();
        (vm, map)
    }

    #[test]
    fn runs_arithmetic_and_exit() {
        let src = r#"
            #[syscall(60)]
            extern fn exit(code @ rdi: u64) -> !;

            #[entry]
            fn main() -> ! {
                bind mut n @ rbx: u64 = 5;
                bind mut acc @ rax: u64 = 1;
                label (loop) {
                    branch (n == 0) => 'done;
                    alt acc *= n;
                    alt n -= 1;
                    branch => 'loop;
                }
                label (done) {
                    alt rdi = acc;
                    call exit { code: rdi @ rdi };
                }
            }
        "#;
        let (mut vm, _) = build(src);
        let out = vm.run(RunMode::Continue, &HashSet::new());
        match out {
            RunOutcome::Exited(code) => assert_eq!(code, 120),
            other => panic!("expected exit(120), got {other:?}"),
        }
    }

    #[test]
    fn write_syscall_captures_stdout() {
        let src = r#"
            bind hello @ .rodata: [u8] = "hi\n";

            #[syscall(1)]
            extern fn write(fd @ rdi: u64, buf @ rsi: *u8, len @ rdx: u64) -> rax: i64;

            #[syscall(60)]
            extern fn exit(code @ rdi: u64) -> !;

            #[entry]
            fn main() -> ! {
                call write { fd: 1, buf: &hello, len: hello.len };
                call exit { code: 0 };
            }
        "#;
        let (mut vm, _) = build(src);
        let out = vm.run(RunMode::Continue, &HashSet::new());
        assert!(matches!(out, RunOutcome::Exited(0)), "got {out:?}");
        assert_eq!(String::from_utf8_lossy(&vm.output), "hi\n");
    }
}
