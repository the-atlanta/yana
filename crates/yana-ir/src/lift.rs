//! Machine IR → SSA-IR construction.
//!
//! The resolver already chose physical registers, so this pass is a
//! **physical-register SSA construction**: every write to a register creates a
//! new version, and joins get physical `phi`s for registers that are live-in.
//! The same data model also carries `Home::Virtual` values, so a future
//! resolver can emit expression temporaries without changing the IR.
//!
//! Algorithm: split into basic blocks from labels/terminators, build the CFG,
//! dominators and dominance frontiers, place pruned phis using block liveness,
//! then rename in dominator-tree order. Source binding events from
//! [`FnBody::bind_events`] are attached to the values they name.

use std::collections::{HashMap, HashSet, VecDeque};

use yana_ast::reg::{GprBase, Reg, RegSize};
use yana_ast::ty::Ty;
use yana_ast::Span;
use yana_codegen::insn::{insn_info, FlagWrite, InsnInfo};
use yana_codegen::ir::{
    BindEventKind, BindKind as CgBindKind, CallContract, Displacement, FnBody, Insn, Jcc, MemOp,
    Operand as MOperand, SpannedInsn, Symbol, SymRet, WideOp,
};

use crate::model::*;

/// Lift a resolved machine module into SSA form.
pub fn lift_module(module: &yana_codegen::Module, source: &str) -> Module {
    let mut functions: Vec<Function> = module
        .bodies
        .iter()
        .map(|body| lift_function(module, body))
        .collect();

    let externs: Vec<Extern> = module
        .symbols
        .iter()
        .enumerate()
        .filter(|(_, s)| matches!(s.kind, yana_codegen::SymbolKind::ExternFn))
        .map(|(idx, s)| Extern {
            symbol: idx,
            name: s.name.clone(),
            params: s
                .params
                .iter()
                .map(|p| ParamDecl {
                    name: p.name.clone(),
                    ty: p.ty.clone(),
                    reg: p.reg,
                    stack: p.stack,
                    span: s.span,
                })
                .collect(),
            ret: ret_ty(s),
            syscall: s.syscall,
            clobbers: s.clobbers.clone(),
            preserves: s.preserves.clone(),
            span: s.span,
        })
        .collect();

    let entry = module
        .entry
        .and_then(|e| functions.iter().position(|f| f.symbol == e));

    let mut stats = Stats {
        symbols: module.symbols.len(),
        functions: functions.len(),
        externs: externs.len(),
        ..Stats::default()
    };
    for f in &functions {
        stats.blocks += f.blocks.len();
        stats.insts += f.blocks.iter().map(|b| b.insts.len()).sum::<usize>();
        stats.values += f.values.len();
        stats.phis += f
            .blocks
            .iter()
            .flat_map(|b| &b.insts)
            .filter(|i| matches!(i.op, Op::Phi { .. }))
            .count();
    }
    Module {
        source: source.to_string(),
        target: module.target.triple().to_string(),
        functions,
        externs,
        entry,
        stats,
    }
}

fn ret_ty(sym: &Symbol) -> RetTy {
    match &sym.ret {
        SymRet::None => RetTy::None,
        SymRet::Never => RetTy::Never,
        SymRet::Single { ty, .. } => RetTy::Single(ty.clone()),
        SymRet::Tuple(parts) => RetTy::Tuple(parts.iter().map(|p| p.ty.clone()).collect()),
    }
}

// ---------------------------------------------------------------------------
// CFG
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct BlockInfo {
    start: usize,
    end: usize,
    label: Option<String>,
    span: Span,
}

struct Cfg {
    blocks: Vec<BlockInfo>,
    insn_block: Vec<usize>,
    label_block: HashMap<usize, usize>,
    succs: Vec<Vec<usize>>,
    preds: Vec<Vec<usize>>,
    reachable: Vec<bool>,
}

fn build_cfg(body: &FnBody) -> Cfg {
    let n = body.insns.len();
    let mut leaders = std::collections::BTreeSet::new();
    if n > 0 {
        leaders.insert(0);
    }
    for def in &body.label_defs {
        leaders.insert(def.at_insn.min(n));
    }
    for (i, si) in body.insns.iter().enumerate() {
        if i + 1 < n && is_block_end(body, &si.insn, i) {
            leaders.insert(i + 1);
        }
    }
    let starts: Vec<usize> = leaders.into_iter().collect();
    let mut blocks = Vec::new();
    for (i, &start) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(n);
        let label = body
            .label_defs
            .iter()
            .find(|d| d.at_insn == start)
            .map(|d| d.name.clone());
        let span = body
            .insns
            .get(start)
            .map(|s| s.span)
            .unwrap_or_else(|| body.insns.last().map(|s| s.span).unwrap_or(Span::DUMMY));
        blocks.push(BlockInfo { start, end, label, span });
    }

    let mut insn_block = vec![0usize; n];
    for (b, info) in blocks.iter().enumerate() {
        for k in info.start..info.end {
            insn_block[k] = b;
        }
    }

    let mut label_block = HashMap::new();
    for (li, def) in body.label_defs.iter().enumerate() {
        if let Some(b) = blocks.iter().position(|info| info.start == def.at_insn.min(n)) {
            label_block.insert(li, b);
        }
    }

    let mut succs = vec![Vec::new(); blocks.len()];
    for b in 0..blocks.len() {
        let info = &blocks[b];
        if info.start == info.end {
            if b + 1 < blocks.len() {
                succs[b].push(b + 1);
            }
            continue;
        }
        let last_idx = info.end - 1;
        let last = &body.insns[last_idx].insn;
        match last {
            Insn::Jmp { label } => {
                if let Some(t) = label_block.get(label) {
                    succs[b].push(*t);
                }
            }
            Insn::Jcc { label, .. } => {
                if let Some(t) = label_block.get(label) {
                    succs[b].push(*t);
                }
                if b + 1 < blocks.len() {
                    succs[b].push(b + 1);
                }
            }
            Insn::Ret | Insn::Int3 | Insn::Ud2 => {}
            Insn::Call { contract, .. } if contract.noreturn => {}
            Insn::Syscall if syscall_noreturn(body, b, last_idx) => {}
            _ => {
                if b + 1 < blocks.len() {
                    succs[b].push(b + 1);
                }
            }
        }
        succs[b].sort_unstable();
        succs[b].dedup();
    }

    let mut preds = vec![Vec::new(); blocks.len()];
    for (b, ss) in succs.iter().enumerate() {
        for &s in ss {
            preds[s].push(b);
        }
    }

    let mut reachable = vec![false; blocks.len()];
    if !blocks.is_empty() {
        let mut q = VecDeque::new();
        reachable[0] = true;
        q.push_back(0usize);
        while let Some(b) = q.pop_front() {
            for &s in &succs[b] {
                if !reachable[s] {
                    reachable[s] = true;
                    q.push_back(s);
                }
            }
        }
    }

    Cfg { blocks, insn_block, label_block, succs, preds, reachable }
}

fn is_block_end(body: &FnBody, insn: &Insn, idx: usize) -> bool {
    match insn {
        Insn::Jmp { .. } | Insn::Jcc { .. } | Insn::Ret | Insn::Int3 | Insn::Ud2 => true,
        Insn::Call { contract, .. } => contract.noreturn,
        Insn::Syscall => syscall_noreturn(body, 0, idx),
        _ => false,
    }
}

/// A `syscall` is a block terminator only for `exit`/`exit_group`; those never
/// return. Detect the number from the nearest preceding `mov rax, imm`.
fn syscall_noreturn(body: &FnBody, block_start: usize, idx: usize) -> bool {
    let mut j = idx;
    while j > block_start {
        j -= 1;
        match &body.insns[j].insn {
            Insn::Mov { dst: MOperand::Reg(r), src: MOperand::Imm(n), .. }
                if loc_of(r) == Some(Loc::Reg(GprBase::A)) =>
            {
                return *n == 60 || *n == 231;
            }
            // Do not scan past a write to rax or a label-ish boundary.
            Insn::Mov { dst: MOperand::Reg(r), .. }
                if loc_of(r) == Some(Loc::Reg(GprBase::A)) =>
            {
                return false;
            }
            _ => {}
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Dominators + dominance frontiers
// ---------------------------------------------------------------------------

struct Dominators {
    idom: Vec<Option<usize>>,
    depth: Vec<usize>,
    df: Vec<Vec<usize>>,
    children: Vec<Vec<usize>>,
}

impl Dominators {
    fn new(cfg: &Cfg) -> Self {
        let n = cfg.blocks.len();
        let mut idom = vec![None; n];
        let mut depth = vec![0usize; n];
        if n == 0 {
            return Dominators { idom, depth, df: vec![], children: vec![] };
        }

        // Reverse postorder of reachable blocks.
        let mut post = Vec::new();
        let mut seen = vec![false; n];
        fn dfs(b: usize, cfg: &Cfg, seen: &mut [bool], post: &mut Vec<usize>) {
            if seen[b] {
                return;
            }
            seen[b] = true;
            for &s in &cfg.succs[b] {
                dfs(s, cfg, seen, post);
            }
            post.push(b);
        }
        dfs(0, cfg, &mut seen, &mut post);
        let mut rpo = post;
        rpo.reverse();
        let mut rpo_num = vec![usize::MAX; n];
        for (i, &b) in rpo.iter().enumerate() {
            rpo_num[b] = i;
        }

        idom[0] = Some(0);
        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter().skip(1) {
                let mut new_idom = None;
                for &p in &cfg.preds[b] {
                    if !cfg.reachable[p] || idom[p].is_none() {
                        continue;
                    }
                    new_idom = Some(match new_idom {
                        None => p,
                        Some(x) => intersect(p, x, &idom, &rpo_num),
                    });
                }
                if let Some(ni) = new_idom {
                    if idom[b] != Some(ni) {
                        idom[b] = Some(ni);
                        changed = true;
                    }
                }
            }
        }

        // Depths from the idom tree (entry = 0).
        for &b in rpo.iter().skip(1) {
            if let Some(parent) = idom[b] {
                depth[b] = depth[parent] + 1;
            }
        }

        let mut df = vec![Vec::new(); n];
        for b in 0..n {
            if !cfg.reachable[b] || cfg.preds[b].len() < 2 {
                continue;
            }
            for &p in &cfg.preds[b] {
                if !cfg.reachable[p] {
                    continue;
                }
                let mut runner = p;
                while Some(runner) != idom[b] {
                    if df[runner].last().copied() != Some(b) {
                        df[runner].push(b);
                    }
                    match idom[runner] {
                        Some(next) if next != runner => runner = next,
                        _ => break,
                    }
                }
            }
        }

        let mut children = vec![Vec::new(); n];
        for b in 0..n {
            if let Some(parent) = idom[b] {
                if parent != b {
                    children[parent].push(b);
                }
            }
        }

        Dominators { idom, depth, df, children }
    }
}

fn intersect(mut a: usize, mut b: usize, idom: &[Option<usize>], rpo_num: &[usize]) -> usize {
    while a != b {
        while rpo_num[a] > rpo_num[b] {
            a = idom[a].unwrap_or(a);
        }
        while rpo_num[b] > rpo_num[a] {
            b = idom[b].unwrap_or(b);
        }
    }
    a
}

// ---------------------------------------------------------------------------
// Liveness (register-level, used to prune phis)
// ---------------------------------------------------------------------------

struct Liveness {
    use_: Vec<HashSet<Loc>>,
    def: Vec<HashSet<Loc>>,
    live_in: Vec<HashSet<Loc>>,
    live_out: Vec<HashSet<Loc>>,
}

impl Liveness {
    fn new(cfg: &Cfg, body: &FnBody) -> Self {
        let n = cfg.blocks.len();
        let mut use_ = vec![HashSet::new(); n];
        let mut def = vec![HashSet::new(); n];

        for (b, info) in cfg.blocks.iter().enumerate() {
            let mut used = HashSet::new();
            let mut defined = HashSet::new();
            for k in info.start..info.end {
                let si = &body.insns[k];
                let ii = insn_info(&si.insn);
                let mut reads: Vec<Loc> = ii.reads.iter().filter_map(loc_of).collect();
                let mut writes: Vec<Loc> = ii.writes.iter().filter_map(loc_of).collect();
                if flags_mask(ii.reads_flags) != 0 {
                    reads.push(Loc::Flags);
                }
                if flags_mask(ii.writes_flags) != 0 {
                    writes.push(Loc::Flags);
                }
                match &si.insn {
                    Insn::Push { .. } | Insn::Pop { .. } | Insn::StackSlot { .. } | Insn::StackPad { .. } => {
                        reads.push(Loc::Reg(GprBase::Sp));
                        writes.push(Loc::Reg(GprBase::Sp));
                    }
                    Insn::Ret => {
                        for r in &body.result_regs {
                            if let Some(l) = loc_of(r) {
                                reads.push(l);
                            }
                        }
                    }
                    Insn::Call { contract, .. } => {
                        reads.extend(contract.args.iter().filter_map(loc_of));
                        writes.extend(contract.results.iter().filter_map(loc_of));
                        writes.extend(contract.clobbers.iter().filter_map(loc_of));
                        writes.push(Loc::Flags);
                    }
                    _ => {}
                }
                for l in reads {
                    if !defined.contains(&l) {
                        used.insert(l);
                    }
                }
                for l in writes {
                    defined.insert(l);
                }
            }
            use_[b] = used;
            def[b] = defined;
        }

        let mut live_in = vec![HashSet::new(); n];
        let mut live_out = vec![HashSet::new(); n];
        let mut changed = true;
        while changed {
            changed = false;
            for b in (0..n).rev() {
                let mut out: HashSet<Loc> = HashSet::new();
                for &s in &cfg.succs[b] {
                    out.extend(live_in[s].iter().copied());
                }
                let mut inn = use_[b].clone();
                for l in &out {
                    if !def[b].contains(l) {
                        inn.insert(*l);
                    }
                }
                if out != live_out[b] || inn != live_in[b] {
                    live_out[b] = out;
                    live_in[b] = inn;
                    changed = true;
                }
            }
        }

        Liveness { use_, def, live_in, live_out }
    }
}

// ---------------------------------------------------------------------------
// Per-function lifter
// ---------------------------------------------------------------------------

struct FnLifter<'a> {
    module: &'a yana_codegen::Module,
    body: &'a FnBody,
    cfg: &'a Cfg,
    phi_locs: &'a [HashSet<Loc>],
    function: Function,
    reg_versions: HashMap<GprBase, u32>,
    flags_versions: u32,
    slot_versions: u32,
    undef_versions: u32,
    phi_values: Vec<HashMap<Loc, ValueId>>,
    phi_meta: Vec<(BlockId, Loc, usize, ValueId)>,
    phi_incoming: HashMap<(BlockId, Loc), Vec<(ValueId, BlockId)>>,
    bind_points: HashSet<usize>,
    /// `unbind name;` events keyed by the flat instruction index *before*
    /// which the `virt unbind` node belongs.
    unbinds_at: HashMap<usize, Vec<(String, Span)>>,
    state_before: HashMap<usize, HashMap<Loc, ValueId>>,
    state_after: HashMap<usize, HashMap<Loc, ValueId>>,
    entry_current: HashMap<Loc, ValueId>,
}

impl<'a> FnLifter<'a> {
    fn new(
        module: &'a yana_codegen::Module,
        body: &'a FnBody,
        cfg: &'a Cfg,
        phi_locs: &'a [HashSet<Loc>],
    ) -> Self {
        let sym = &module.symbols[body.symbol];
        let is_entry = module.entry == Some(body.symbol);
        let mut stack_depth = 0i32;
        let mut max_depth = 0i32;
        for si in &body.insns {
            let ii = insn_info(&si.insn);
            stack_depth -= ii.stack_delta;
            max_depth = max_depth.max(stack_depth);
        }

        let blocks = cfg
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| Block {
                id: i as BlockId,
                label: b.label.clone().or_else(|| if i == 0 { Some("entry".into()) } else { None }),
                insts: Vec::new(),
                preds: cfg.preds[i].iter().map(|x| *x as BlockId).collect(),
                succs: cfg.succs[i].iter().map(|x| *x as BlockId).collect(),
                span: b.span,
                reachable: cfg.reachable[i],
            })
            .collect();

        let function = Function {
            symbol: body.symbol,
            name: sym.name.clone(),
            source_name: sym.source_name.clone(),
            params: Vec::new(),
            ret: ret_ty(sym),
            blocks,
            values: Vec::new(),
            bindings: Vec::new(),
            clobbers: sym.clobbers.clone(),
            preserves: sym.preserves.clone(),
            stack: StackInfo {
                frame: 0,
                max_depth,
                alignment: 16,
            },
            span: sym.span,
            is_entry,
            returns_never: body.returns_never,
        };

        let mut l = FnLifter {
            module,
            body,
            cfg,
            phi_locs,
            function,
            reg_versions: HashMap::new(),
            flags_versions: 0,
            slot_versions: 0,
            undef_versions: 0,
            phi_values: vec![HashMap::new(); cfg.blocks.len()],
            phi_meta: Vec::new(),
            phi_incoming: HashMap::new(),
            bind_points: body.bind_events.iter().map(|e| e.insn).collect(),
            unbinds_at: body
                .bind_events
                .iter()
                .filter(|e| matches!(e.kind, BindEventKind::Unbind))
                .fold(HashMap::new(), |mut m, e| {
                    m.entry(e.insn).or_insert_with(Vec::new).push((e.name.clone(), e.span));
                    m
                }),
            state_before: HashMap::new(),
            state_after: HashMap::new(),
            entry_current: HashMap::new(),
        };
        l.init_params();
        l.init_phis();
        l.init_stack_entry();
        l
    }

    /// Make the incoming `rsp` explicit: `%rsp.0 = stack.entry`.
    fn init_stack_entry(&mut self) {
        if self.cfg.blocks.is_empty() || !self.cfg.reachable[0] {
            return;
        }
        let loc = Loc::Reg(GprBase::Sp);
        if self.entry_current.contains_key(&loc) {
            return;
        }
        let base = GprBase::Sp;
        let version = self.reg_versions.entry(base).or_insert(0);
        let name = format!("%{}.{}", reg64(base).name(), *version);
        *version += 1;
        let v = self.push_value(
            name.clone(),
            Ty::Ptr(Box::new(Ty::U8)),
            Home::Fixed(reg64(base), FixedKind::Stack),
            ValueKind::StackPtr,
            self.function.span,
            64,
            false,
            None,
        );
        self.entry_current.insert(loc, v);
        self.function.values[v as usize].def = Some(DefSite { block: 0, inst: 0 });
        self.function.blocks[0].insts.push(Inst {
            op: Op::StackEntry { sp: v },
            span: self.function.span,
            text: format!("{name} = stack.entry"),
            defs: vec![v],
            uses: Vec::new(),
            effects: Effects::default(),
            machine: None,
            comment: Some("[abi] kernel/ABI entry state; no instruction emitted".into()),
        });
    }

    fn init_params(&mut self) {
        let sym = &self.module.symbols[self.body.symbol];
        let params: Vec<_> = sym
            .params
            .iter()
            .filter_map(|p| p.reg.map(|reg| (p.name.clone(), p.ty.clone(), reg, p.stack)))
            .collect();
        for (name, ty, reg, _stack) in params {
            let loc = match loc_of(&reg) {
                Some(l) => l,
                None => continue,
            };
            let base = match loc {
                Loc::Reg(b) => b,
                _ => continue,
            };
            let version = self.reg_versions.entry(base).or_insert(0);
            let name_v = format!("%{}.{}", reg64(base).name(), *version);
            *version += 1;
            let v = self.push_value(
                name_v,
                ty.clone(),
                Home::Fixed(reg64(base), FixedKind::AbiArg),
                ValueKind::Reg,
                sym.span,
                64,
                false,
                None,
            );
            self.entry_current.insert(loc, v);
            let idx = self.function.bindings.len();
            self.function.bindings.push(Binding {
                name: name.clone(),
                reg: Some(reg64(base)),
                ty,
                span: sym.span,
                kind: BindKind::Param,
                value: Some(v),
                active_from: 0,
                retired_at: None,
            });
            self.function.values[v as usize].bind = Some(idx);
            self.function.params.push(Param {
                name,
                ty: self.function.values[v as usize].ty.clone(),
                reg: reg64(base),
                value: v,
                span: sym.span,
            });
        }
    }

    fn init_phis(&mut self) {
        for b in 0..self.cfg.blocks.len() {
            if !self.cfg.reachable[b] {
                continue;
            }
            for loc in all_locs() {
                if !self.phi_locs[b].contains(&loc) {
                    continue;
                }
                let span = self.cfg.blocks[b].span;
                let v = match loc {
                    Loc::Reg(base) => {
                        let version = self.reg_versions.entry(base).or_insert(0);
                        let name = format!("%{}.{}", reg64(base).name(), *version);
                        *version += 1;
                        let home = if base == GprBase::Sp {
                            Home::Fixed(reg64(base), FixedKind::Stack)
                        } else {
                            Home::Pinned(reg64(base))
                        };
                        self.push_value(
                            name,
                            Ty::U64,
                            home,
                            if base == GprBase::Sp { ValueKind::StackPtr } else { ValueKind::Reg },
                            span,
                            64,
                            false,
                            None,
                        )
                    }
                    Loc::Flags => {
                        let version = self.flags_versions;
                        self.flags_versions += 1;
                        self.push_value(
                            format!("%flags.{version}"),
                            Ty::U64,
                            Home::Virtual,
                            ValueKind::Flags,
                            span,
                            64,
                            false,
                            None,
                        )
                    }
                };
                let idx = self.function.blocks[b].insts.len();
                self.function.values[v as usize].def = Some(DefSite { block: b as BlockId, inst: idx });
                self.phi_values[b].insert(loc, v);
                self.phi_meta.push((b as BlockId, loc, idx, v));
                self.function.blocks[b].insts.push(Inst {
                    op: Op::Phi { incoming: Vec::new() },
                    span,
                    text: String::new(),
                    defs: vec![v],
                    uses: Vec::new(),
                    effects: Effects::default(),
                    machine: None,
                    comment: Some("[ssa] physical phi".into()),
                });
            }
        }
    }

    fn run(&mut self, dom: &Dominators) {
        if !self.cfg.blocks.is_empty() {
            let mut current = self.entry_current.clone();
            self.rename_block(0, &mut current, dom);
        }
        for b in 0..self.cfg.blocks.len() {
            if !self.cfg.reachable[b] {
                let mut current = HashMap::new();
                self.rename_unreachable(b, &mut current);
            }
        }
        self.append_trailing_unbinds();
        self.finish_phis();
        self.finish_bindings();
    }

    fn append_trailing_unbinds(&mut self) {
        let n = self.body.insns.len();
        let mut trailing: Vec<(String, Span)> = self
            .body
            .bind_events
            .iter()
            .filter(|e| matches!(e.kind, BindEventKind::Unbind) && e.insn >= n)
            .map(|e| (e.name.clone(), e.span))
            .collect();
        if trailing.is_empty() {
            return;
        }
        let b = self
            .function
            .blocks
            .iter()
            .rposition(|b| !b.insts.is_empty())
            .unwrap_or(0);
        for (name, span) in trailing.drain(..) {
            self.function.blocks[b].insts.push(virt_unbind_inst(name, span));
        }
    }

    fn rename_block(&mut self, b: usize, current: &mut HashMap<Loc, ValueId>, dom: &Dominators) {
        // Sibling subtrees in the dominator tree must not see each other's
        // definitions. Save the incoming map and restore it on exit; the
        // block's own post-state is only used to fill successor phi edges.
        let saved = current.clone();

        for loc in all_locs() {
            if let Some(&v) = self.phi_values[b].get(&loc) {
                current.insert(loc, v);
            }
        }

        let info = self.cfg.blocks[b].clone();
        for k in info.start..info.end {
            if let Some(events) = self.unbinds_at.get(&k).cloned() {
                for (name, span) in events {
                    self.function.blocks[b].insts.push(virt_unbind_inst(name, span));
                }
            }
            let local = self.function.blocks[b].insts.len();
            let si = self.body.insns[k].clone();
            if self.bind_points.contains(&k) {
                self.state_before.insert(k, current.clone());
            }
            let inst = self.lift_insn(b, local, k, &si, current);
            self.function.blocks[b].insts.push(inst);
            if self.bind_points.contains(&k) {
                self.state_after.insert(k, current.clone());
            }
        }

        // A noreturn call/syscall has no fallthrough edge. Make that explicit
        // in the IR, the same way LLVM requires `unreachable` after `noreturn`.
        if matches!(
            self.function.blocks[b].insts.last().map(|i| &i.op),
            Some(Op::Call { noreturn: true, .. }) | Some(Op::Syscall { noreturn: true, .. })
        ) {
            let span = self
                .function
                .blocks[b]
                .insts
                .last()
                .map(|i| i.span)
                .unwrap_or(self.cfg.blocks[b].span);
            self.function.blocks[b].insts.push(Inst {
                op: Op::Unreachable,
                span,
                text: "unreachable".into(),
                defs: Vec::new(),
                uses: Vec::new(),
                effects: Effects::default(),
                machine: None,
                comment: Some("[verify] noreturn: no fallthrough edge".into()),
            });
        }

        for &s in &self.cfg.succs[b] {
            for loc in all_locs() {
                if !self.phi_locs[s].contains(&loc) {
                    continue;
                }
                let v = self.cur(current, loc, self.cfg.blocks[b].span);
                self.phi_incoming
                    .entry((s as BlockId, loc))
                    .or_default()
                    .push((v, b as BlockId));
            }
        }

        for &child in &dom.children[b] {
            if self.cfg.reachable[child] {
                self.rename_block(child, current, dom);
            }
        }

        *current = saved;
    }

    fn rename_unreachable(&mut self, b: usize, current: &mut HashMap<Loc, ValueId>) {
        let info = self.cfg.blocks[b].clone();
        for k in info.start..info.end {
            if let Some(events) = self.unbinds_at.get(&k).cloned() {
                for (name, span) in events {
                    self.function.blocks[b].insts.push(virt_unbind_inst(name, span));
                }
            }
            let local = self.function.blocks[b].insts.len();
            let si = self.body.insns[k].clone();
            if self.bind_points.contains(&k) {
                self.state_before.insert(k, current.clone());
            }
            let inst = self.lift_insn(b, local, k, &si, current);
            self.function.blocks[b].insts.push(inst);
            if self.bind_points.contains(&k) {
                self.state_after.insert(k, current.clone());
            }
        }
    }

    fn finish_phis(&mut self) {
        for (b, loc, idx, v) in self.phi_meta.clone() {
            let incoming = self
                .phi_incoming
                .get(&(b, loc))
                .cloned()
                .unwrap_or_default();
            let uses: Vec<ValueId> = incoming.iter().map(|(v, _)| *v).collect();
            let text = if incoming.is_empty() {
                format!("{} = phi {} <empty>", self.vname(v), self.vty(v))
            } else {
                let parts: Vec<String> = incoming
                    .iter()
                    .map(|(val, pred)| {
                        format!(
                            "[ {}, %{} ]",
                            self.vname(*val),
                            self.block_name(*pred)
                        )
                    })
                    .collect();
                format!("{} = phi {} {}", self.vname(v), self.vty(v), parts.join(", "))
            };
            if let Some(inst) = self.function.blocks[b as usize].insts.get_mut(idx) {
                inst.op = Op::Phi { incoming };
                inst.text = text;
                inst.uses = uses;
            }
        }
    }

    fn finish_bindings(&mut self) {
        let events = self.body.bind_events.clone();
        for event in &events {
            match event.kind {
                BindEventKind::Unbind => {
                    if let Some(idx) = self
                        .function
                        .bindings
                        .iter()
                        .rposition(|b| b.name == event.name && b.retired_at.is_none())
                    {
                        self.function.bindings[idx].retired_at = Some(event.insn);
                    }
                }
                BindEventKind::Bind(CgBindKind::Param) => {}
                BindEventKind::Bind(kind) => {
                    let state = if event.has_init {
                        self.state_after
                            .get(&event.insn)
                            .or_else(|| self.state_after.get(&event.insn.saturating_sub(1)))
                    } else {
                        self.state_before.get(&event.insn)
                    };
                    let value = event
                        .reg
                        .and_then(|r| loc_of(&r))
                        .and_then(|loc| state.and_then(|s| s.get(&loc)).copied());
                    let idx = self.function.bindings.len();
                    self.function.bindings.push(Binding {
                        name: event.name.clone(),
                        reg: event.reg,
                        ty: event.ty.clone(),
                        span: event.span,
                        kind: match kind {
                            CgBindKind::Param => BindKind::Param,
                            CgBindKind::Local => BindKind::Local,
                            CgBindKind::Discard => BindKind::Discard,
                            CgBindKind::ReturnPlace => BindKind::ReturnPlace,
                        },
                        value,
                        active_from: event.insn,
                        retired_at: None,
                    });
                    if let Some(v) = value {
                        self.function.values[v as usize].bind = Some(idx);
                        if !is_plain_int(&event.ty) {
                            self.function.values[v as usize].ty = event.ty.clone();
                        }
                    }
                }
            }
        }

        // The `-> rax` return place: attach the value that `ret` actually uses.
        if let Some(ret) = self.find_ret_value() {
            let reg = self.body.result_regs.first().copied();
            let ty = reg
                .and_then(|r| {
                    self.function
                        .params
                        .iter()
                        .find(|p| p.reg == r)
                        .map(|p| p.ty.clone())
                })
                .unwrap_or(Ty::U64);
            let idx = self.function.bindings.len();
            let name = reg.map(|r| r.name().to_string()).unwrap_or_else(|| "ret".into());
            self.function.bindings.push(Binding {
                name,
                reg,
                ty,
                span: self.function.span,
                kind: BindKind::ReturnPlace,
                value: Some(ret),
                active_from: 0,
                retired_at: None,
            });
            self.function.values[ret as usize].bind = Some(idx);
        }
    }

    fn find_ret_value(&self) -> Option<ValueId> {
        for b in &self.function.blocks {
            for i in &b.insts {
                if let Op::Ret { value: Some(v) } = &i.op {
                    return Some(*v);
                }
            }
        }
        None
    }

    // -- instruction lifting ------------------------------------------------

    fn lift_insn(
        &mut self,
        b: usize,
        local: usize,
        flat: usize,
        si: &SpannedInsn,
        current: &mut HashMap<Loc, ValueId>,
    ) -> Inst {
        let span = si.span;
        let ii = insn_info(&si.insn);
        let mut defs: Vec<ValueId> = Vec::new();
        let mut uses: Vec<ValueId> = Vec::new();
        let mut comment: Option<String> = None;
        let op: Op;
        let text: String;

        match &si.insn {
            Insn::Mov { dst, src, size } => {
                let src_op = self.read_op(src, current, span);
                uses.extend(self.operand_uses(&src_op));
                let width = size_bits(*size, dst);
                let (dst_op, d, dst_ty) = match dst {
                    MOperand::Reg(r) => {
                        let partial = width < 32;
                        let cv = match &src_op {
                            Operand::Imm(i) => Some(*i),
                            _ => None,
                        };
                        let ty = match &src_op {
                            Operand::Value(src_v) => {
                                let t = self.function.values[*src_v as usize].ty.clone();
                                if is_plain_int(&t) { ty_for_width_ty(width) } else { t }
                            }
                            _ => ty_for_width_ty(width),
                        };
                        let v = self.def_reg_ty(current, r, ty.clone(), span, width, partial, cv);
                        (Operand::Value(v), vec![v], ty)
                    }
                    MOperand::Mem(m) => {
                        let mem = self.rewrite_mem(m, current, span);
                        uses.extend(self.mem_uses(&mem));
                        (Operand::Mem(mem), Vec::new(), ty_for_width_ty(width))
                    }
                    _ => (self.read_op(dst, current, span), Vec::new(), ty_for_width_ty(width)),
                };
                defs.extend(d);
                text = match &dst_op {
                    Operand::Mem(_) => format!(
                        "store {} {}, {}",
                        ty_for_width(width),
                        self.render_op(&src_op),
                        self.render_op(&dst_op)
                    ),
                    _ => format!(
                        "{} = mov {} {}",
                        self.render_defs(&defs),
                        ty_str(&dst_ty),
                        self.render_op(&src_op)
                    ),
                };
                op = Op::Mov { dst: dst_op, src: src_op, size: width };
            }
            Insn::Movzx { dst, src, src_size, dst_size } => {
                let src_op = self.read_op(src, current, span);
                uses.extend(self.operand_uses(&src_op));
                let v = self.def_reg(current, dst, span, *dst_size, false, None);
                defs.push(v);
                text = format!(
                    "{} = movzx {} {}",
                    self.vname(v),
                    ty_for_width(*dst_size),
                    self.render_op(&src_op)
                );
                let _ = src_size;
                op = Op::Mov { dst: Operand::Value(v), src: src_op, size: *dst_size };
            }
            Insn::Movsx { dst, src, src_size, dst_size } => {
                let src_op = self.read_op(src, current, span);
                uses.extend(self.operand_uses(&src_op));
                let v = self.def_reg(current, dst, span, *dst_size, false, None);
                defs.push(v);
                text = format!(
                    "{} = movsx {} {}",
                    self.vname(v),
                    ty_for_width(*dst_size),
                    self.render_op(&src_op)
                );
                let _ = src_size;
                op = Op::Mov { dst: Operand::Value(v), src: src_op, size: *dst_size };
            }
            Insn::Lea { dst, addr } => {
                let mem = self.rewrite_mem(addr, current, span);
                uses.extend(self.mem_uses(&mem));
                let v = self.def_reg(current, dst, span, 64, false, None);
                defs.push(v);
                text = format!("{} = lea ptr {}", self.vname(v), self.render_mem(&mem));
                op = Op::Lea { dst: v, addr: mem };
            }
            Insn::LeaSym { dst, sym, add } => {
                let mem = Mem {
                    base: None,
                    index: None,
                    scale: 1,
                    disp: Displacement::Sym { sym: *sym, add: *add },
                    size: 64,
                    rip_relative: true,
                };
                let v = self.def_reg(current, dst, span, 64, false, None);
                defs.push(v);
                text = format!("{} = lea ptr {}", self.vname(v), self.render_mem(&mem));
                op = Op::Lea { dst: v, addr: mem };
            }
            Insn::Push { src, size } => {
                let value = self.read_op(src, current, span);
                uses.extend(self.operand_uses(&value));
                let sp_in = self.cur(current, Loc::Reg(GprBase::Sp), span);
                let sp_out = self.def_reg(current, &reg64(GprBase::Sp), span, 64, false, None);
                let slot = self.new_slot(span);
                defs.push(sp_out);
                defs.push(slot);
                text = format!(
                    "{}, {} = push {} {}, {}",
                    self.vname(sp_out),
                    self.vname(slot),
                    ty_for_width(*size),
                    self.render_op(&value),
                    self.vname(sp_in)
                );
                op = Op::Push { value, sp_in, sp_out, slot };
            }
            Insn::StackSlot { grow } => {
                let sp_in = self.cur(current, Loc::Reg(GprBase::Sp), span);
                let sp_out = self.def_reg(current, &reg64(GprBase::Sp), span, 64, false, None);
                defs.push(sp_out);
                let delta = if *grow { -8 } else { 8 };
                text = format!(
                    "{} = stackslot {}, {delta}",
                    self.vname(sp_out),
                    self.vname(sp_in)
                );
                comment = Some("[resolve] stack-slot adjustment; no data value".into());
                op = Op::StackSlot { sp_in, sp_out, grow: *grow };
            }
            Insn::StackPad { pad } => {
                let sp_in = self.cur(current, Loc::Reg(GprBase::Sp), span);
                let sp_out = self.def_reg(current, &reg64(GprBase::Sp), span, 64, false, None);
                defs.push(sp_out);
                text = format!(
                    "{} = stackpad {}, -{pad}",
                    self.vname(sp_out),
                    self.vname(sp_in)
                );
                op = Op::StackPad { sp_in, sp_out, pad: *pad };
            }
            Insn::StackAlign { align } => {
                let sp_in = self.cur(current, Loc::Reg(GprBase::Sp), span);
                let sp_out = self.def_reg(current, &reg64(GprBase::Sp), span, 64, false, None);
                defs.push(sp_out);
                text = format!(
                    "{} = stackalign {}, {}",
                    self.vname(sp_out),
                    self.vname(sp_in),
                    align
                );
                comment = Some(format!(
                    "[abi] `align {align}` not lowered yet; stack analysis computes the pad"
                ));
                op = Op::StackPad { sp_in, sp_out, pad: 0 };
            }
            Insn::Pop { dst, size } => {
                let sp_in = self.cur(current, Loc::Reg(GprBase::Sp), span);
                let sp_out = self.def_reg(current, &reg64(GprBase::Sp), span, 64, false, None);
                defs.push(sp_out);
                let place = match dst {
                    MOperand::Reg(r) => {
                        let v = self.def_reg(current, r, span, *size, false, None);
                        defs.push(v);
                        Some(Operand::Value(v))
                    }
                    MOperand::Mem(m) => {
                        let mem = self.rewrite_mem(m, current, span);
                        uses.extend(self.mem_uses(&mem));
                        Some(Operand::Mem(mem))
                    }
                    other => Some(self.read_op(other, current, span)),
                };
                text = match &place {
                    Some(p) => format!(
                        "{}, {} = pop {}, {}",
                        self.vname(sp_out),
                        self.render_op(p),
                        ty_for_width(*size),
                        self.vname(sp_in)
                    ),
                    None => format!(
                        "{} = pop {}, {}",
                        self.vname(sp_out),
                        ty_for_width(*size),
                        self.vname(sp_in)
                    ),
                };
                op = Op::Pop { sp_in, sp_out, dst: place };
            }
            Insn::Add { dst, src, size } => {
                let (o, t) = self.lift_alu(AluOp::Add, "add", dst, src, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::Sub { dst, src, size } => {
                let (o, t) = self.lift_alu(AluOp::Sub, "sub", dst, src, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::And { dst, src, size } => {
                let (o, t) = self.lift_alu(AluOp::And, "and", dst, src, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::Or { dst, src, size } => {
                let (o, t) = self.lift_alu(AluOp::Or, "or", dst, src, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::Xor { dst, src, size } => {
                let (o, t) = self.lift_alu(AluOp::Xor, "xor", dst, src, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::Shl { dst, src, size } => {
                let (o, t) = self.lift_alu(AluOp::Shl, "shl", dst, src, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::Shr { dst, src, size } => {
                let (o, t) = self.lift_alu(AluOp::Shr, "shr", dst, src, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::Imul2 { dst, src, size } => {
                let (o, t) = self.lift_alu(AluOp::Imul, "imul", dst, src, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::Neg { dst, size } => {
                let (o, t) = self.lift_unary(AluOp::Neg, "neg", dst, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::Not { dst, size } => {
                let (o, t) = self.lift_unary(AluOp::Not, "not", dst, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::Inc { dst, size } => {
                let (o, t) = self.lift_unary(AluOp::Inc, "inc", dst, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::Dec { dst, size } => {
                let (o, t) = self.lift_unary(AluOp::Dec, "dec", dst, *size, current, span, &mut defs, &mut uses);
                op = o;
                text = t;
            }
            Insn::Cmp { a, b, size } => {
                let a = self.read_op(a, current, span);
                let b = self.read_op(b, current, span);
                uses.extend(self.operand_uses(&a));
                uses.extend(self.operand_uses(&b));
                let f = self.def_flags(current, span);
                defs.push(f);
                text = format!(
                    "{} = cmp {} {}, {}",
                    self.vname(f),
                    ty_for_width(*size),
                    self.render_op(&a),
                    self.render_op(&b)
                );
                op = Op::Cmp { a, b, size: *size };
            }
            Insn::Jmp { label } => {
                let target = self.target_block(*label);
                text = format!("br label %{}", self.block_name(target));
                op = Op::Jmp { target };
            }
            Insn::Jcc { cc, label } => {
                let target = self.target_block(*label);
                let flags = self.cur(current, Loc::Flags, span);
                uses.push(flags);
                let fall = self
                    .cfg
                    .succs[b]
                    .iter()
                    .copied()
                    .find(|s| *s != target as usize)
                    .map(|s| s as BlockId);
                text = match fall {
                    Some(f) => format!(
                        "br i1 {}, label %{}, label %{}",
                        self.vname(flags),
                        self.block_name(target),
                        self.block_name(f)
                    ),
                    None => format!("br i1 {}, label %{}", self.vname(flags), self.block_name(target)),
                };
                op = Op::Jcc { cc: *cc, flags, target, fallthrough: fall };
            }
            Insn::Call { sym, contract } => {
                let callee = self.module.symbols[*sym].name.clone();
                let result_tys = match &self.module.symbols[*sym].ret {
                    SymRet::Single { ty, .. } => vec![ty.clone()],
                    SymRet::Tuple(parts) => parts.iter().map(|p| p.ty.clone()).collect(),
                    _ => Vec::new(),
                };
                let mut args = Vec::new();
                for r in &contract.args {
                    if let Some(loc) = loc_of(r) {
                        let v = self.cur(current, loc, span);
                        uses.push(v);
                        args.push(Operand::Value(v));
                    }
                }
                for r in &ii.reads {
                    if let Some(loc) = loc_of(r) {
                        let v = self.cur(current, loc, span);
                        if !uses.contains(&v) {
                            uses.push(v);
                        }
                    }
                }
                let mut results = Vec::new();
                for (i, r) in contract.results.iter().enumerate() {
                    if let Some(loc) = loc_of(r) {
                        let ty = result_tys.get(i).cloned().unwrap_or(Ty::U64);
                        let v = self.def_reg_ty(current, r, ty, span, 64, false, None);
                        defs.push(v);
                        results.push(v);
                        let _ = loc;
                    }
                }
                let mut clobbers = Vec::new();
                for r in &contract.clobbers {
                    if let Some(loc) = loc_of(r) {
                        if contract.results.iter().any(|x| loc_of(x) == Some(loc)) {
                            continue;
                        }
                        let v = self.def_reg(current, r, span, 64, false, None);
                        defs.push(v);
                        clobbers.push(v);
                    }
                }
                let f = self.def_flags(current, span);
                defs.push(f);
                let mut t = if results.is_empty() {
                    format!("call @{callee}(")
                } else {
                    format!("{} = call @{callee}(", self.render_defs(&results))
                };
                t.push_str(
                    &args
                        .iter()
                        .map(|a| self.render_op(a))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                t.push(')');
                if contract.noreturn {
                    t = format!("call noreturn @{callee}({})", args.iter().map(|a| self.render_op(a)).collect::<Vec<_>>().join(", "));
                }
                text = t;
                if let Some(n) = contract.syscall {
                    comment = Some(format!("[contract] syscall {n}; clobbers: {}", regs_str(&contract.clobbers)));
                } else {
                    comment = Some(format!(
                        "[contract] clobbers: {}; noreturn={}",
                        regs_str(&contract.clobbers),
                        contract.noreturn
                    ));
                }
                op = Op::Call {
                    callee: *sym,
                    args,
                    results,
                    clobbers,
                    noreturn: contract.noreturn,
                    syscall: contract.syscall,
                    contract: contract.clone(),
                };
            }
            Insn::Syscall => {
                let nr = self.syscall_number(b, flat).unwrap_or(-1);
                let name = self.syscall_name(nr);
                let mut args = Vec::new();
                let mut results = Vec::new();
                let mut clobbers = Vec::new();
                for r in &ii.reads {
                    if let Some(loc) = loc_of(r) {
                        // Only registers that actually have a value at this
                        // point are operands. `syscall` nominally names r10,
                        // r8, r9 too, but an unused argument is not a use.
                        if loc == Loc::Reg(GprBase::A) {
                            if let Some(&v) = current.get(&loc) {
                                uses.push(v);
                            }
                            continue;
                        }
                        if let Some(&v) = current.get(&loc) {
                            uses.push(v);
                            args.push(Operand::Value(v));
                        }
                    }
                }
                for r in &ii.writes {
                    if let Some(loc) = loc_of(r) {
                        let v = self.def_reg(current, r, span, 64, false, None);
                        defs.push(v);
                        if loc == Loc::Reg(GprBase::A) {
                            results.push(v);
                        } else {
                            clobbers.push(v);
                        }
                    }
                }
                if ii.writes_flags.any() {
                    let f = self.def_flags(current, span);
                    defs.push(f);
                }
                let noreturn = nr == 60 || nr == 231;
                let rendered = self.render_defs(&defs);
                let mut t = if rendered.is_empty() {
                    format!("syscall @{name}(")
                } else {
                    format!("{rendered} = syscall @{name}(")
                };
                t.push_str(
                    &args
                        .iter()
                        .map(|a| self.render_op(a))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                t.push(')');
                text = t;
                comment = Some(format!("[abi] syscall nr {nr}; clobbers: rcx, r11"));
                op = Op::Syscall { args, results, clobbers, noreturn };
            }
            Insn::Ret => {
                let value = self
                    .body
                    .result_regs
                    .first()
                    .and_then(|r| loc_of(r))
                    .map(|loc| self.cur(current, loc, span));
                if let Some(v) = value {
                    uses.push(v);
                }
                text = match value {
                    Some(v) => format!("ret {} {}", self.vty(v), self.vname(v)),
                    None => "ret void".to_string(),
                };
                op = Op::Ret { value };
            }
            Insn::Int3 => {
                text = "int3".into();
                op = Op::Int3;
            }
            Insn::Ud2 => {
                text = "ud2".into();
                op = Op::Ud2;
            }
            Insn::Nop => {
                text = "nop".into();
                op = Op::Nop;
            }
            Insn::MulWide { src, signed, size } => {
                let src_op = self.read_op(src, current, span);
                uses.extend(self.operand_uses(&src_op));
                let a = self.def_reg(current, &reg64(GprBase::A), span, 64, false, None);
                let d = self.def_reg(current, &reg64(GprBase::D), span, 64, false, None);
                defs.push(a);
                defs.push(d);
                let f = self.def_flags(current, span);
                defs.push(f);
                text = format!(
                    "{}, {} = {} {} {}, {}",
                    self.vname(a),
                    self.vname(d),
                    if *signed { "imul" } else { "mul" },
                    ty_for_width(*size),
                    self.render_op(&src_op),
                    self.vname(f)
                );
                op = Op::Raw;
            }
            Insn::DivWide { src, op: wop, size } => {
                let src_op = self.read_op(src, current, span);
                uses.extend(self.operand_uses(&src_op));
                let a = self.def_reg(current, &reg64(GprBase::A), span, 64, false, None);
                let d = self.def_reg(current, &reg64(GprBase::D), span, 64, false, None);
                defs.push(a);
                defs.push(d);
                let f = self.def_flags(current, span);
                defs.push(f);
                text = format!(
                    "{}, {} = {} {} {}, {}",
                    self.vname(a),
                    self.vname(d),
                    match wop { WideOp::Unsigned => "div", WideOp::Signed => "idiv" },
                    ty_for_width(*size),
                    self.render_op(&src_op),
                    self.vname(f)
                );
                op = Op::Raw;
            }
            Insn::ExtendPair { signed, size } => {
                let d = self.def_reg(current, &reg64(GprBase::D), span, 64, false, None);
                defs.push(d);
                text = format!(
                    "{} = {}",
                    self.vname(d),
                    if *signed { if *size == 64 { "cqo" } else { "cdq" } } else { "xor edx, edx" }
                );
                op = Op::Raw;
            }
            Insn::Xchg { a, b, size } => {
                let a_op = self.read_op(a, current, span);
                let b_op = self.read_op(b, current, span);
                uses.extend(self.operand_uses(&a_op));
                uses.extend(self.operand_uses(&b_op));
                let mut d = Vec::new();
                for o in [a, b] {
                    if let MOperand::Reg(r) = o {
                        d.push(self.def_reg(current, r, span, *size, false, None));
                    }
                }
                defs.extend(d);
                text = format!(
                    "{} = xchg {} {}, {}",
                    self.render_defs(&defs),
                    ty_for_width(*size),
                    self.render_op(&a_op),
                    self.render_op(&b_op)
                );
                op = Op::Raw;
            }
            Insn::AtomicRMW { op: aop, dst, src, size, .. } => {
                let dst_op = self.read_op(dst, current, span);
                let src_op = self.read_op(src, current, span);
                uses.extend(self.operand_uses(&dst_op));
                uses.extend(self.operand_uses(&src_op));
                if let MOperand::Reg(r) = dst {
                    let v = self.def_reg(current, r, span, *size, false, None);
                    defs.push(v);
                }
                let f = self.def_flags(current, span);
                defs.push(f);
                text = format!(
                    "{} = atomicrmw {:?} {}, {}, {}",
                    self.render_defs(&defs),
                    aop,
                    ty_for_width(*size),
                    self.render_op(&dst_op),
                    self.render_op(&src_op)
                );
                op = Op::Raw;
            }
            Insn::Volatile(inner) => {
                let mut nested = SpannedInsn::new((**inner).clone(), span);
                nested.comment = None;
                let mut inst = self.lift_insn(b, local, flat, &nested, current);
                inst.text = format!("volatile {{ {} }}", inst.text);
                inst.effects.is_volatile = true;
                return inst;
            }
        }

        let effects = effects_of(&si.insn, &ii);
        let mut inst = Inst {
            op,
            span,
            text,
            defs: defs.clone(),
            uses: uses.clone(),
            effects: effects.clone(),
            machine: Some(si.insn.clone()),
            comment,
        };
        for v in &defs {
            self.function.values[*v as usize].def = Some(DefSite { block: b as BlockId, inst: local });
        }
        // A call's result type can be richer than the register width.
        if let Op::Call { results, .. } = &inst.op {
            for &v in results {
                if let Some(sym) = self.call_ret_ty(v) {
                    let _ = sym;
                }
            }
        }
        if inst.comment.is_none() {
            if effects.writes_any_flags() {
                let f = defs
                    .iter()
                    .find(|v| self.function.values[**v as usize].kind == ValueKind::Flags);
                if let Some(f) = f {
                    inst.comment = Some(format!("[flags] -> {}", self.vname(*f)));
                }
            }
        }
        inst
    }

    fn call_ret_ty(&self, _v: ValueId) -> Option<()> {
        None
    }

    fn lift_alu(
        &mut self,
        op: AluOp,
        mnemonic: &str,
        dst: &MOperand,
        src: &MOperand,
        size: u32,
        current: &mut HashMap<Loc, ValueId>,
        span: Span,
        defs: &mut Vec<ValueId>,
        uses: &mut Vec<ValueId>,
    ) -> (Op, String) {
        let rhs = self.read_op(src, current, span);
        uses.extend(self.operand_uses(&rhs));
        let (place, lhs) = match dst {
            MOperand::Reg(r) => {
                let Some(loc) = loc_of(r) else {
                    return (Op::Raw, format!("raw {r:?}"));
                };
                let old = self.cur(current, loc, span);
                uses.push(old);
                let v = self.def_reg(current, r, span, size, false, None);
                defs.push(v);
                (Operand::Value(v), Some(old))
            }
            MOperand::Mem(m) => {
                let mem = self.rewrite_mem(m, current, span);
                uses.extend(self.mem_uses(&mem));
                (Operand::Mem(mem), None)
            }
            other => (self.read_op(other, current, span), None),
        };
        let text = match (&place, lhs) {
            (Operand::Value(v), Some(old)) => format!(
                "{} = {} {} {}, {}",
                self.vname(*v),
                mnemonic,
                ty_for_width(size),
                self.vname(old),
                self.render_op(&rhs)
            ),
            (Operand::Mem(_), _) => format!(
                "{} {} {}, {}",
                mnemonic,
                ty_for_width(size),
                self.render_op(&rhs),
                self.render_op(&place)
            ),
            _ => format!("{} {}, {}", mnemonic, ty_for_width(size), self.render_op(&rhs)),
        };
        (Op::Alu { op, dst: place, lhs, rhs, size }, text)
    }

    fn lift_unary(
        &mut self,
        op: AluOp,
        mnemonic: &str,
        dst: &MOperand,
        size: u32,
        current: &mut HashMap<Loc, ValueId>,
        span: Span,
        defs: &mut Vec<ValueId>,
        uses: &mut Vec<ValueId>,
    ) -> (Op, String) {
        let (place, lhs) = match dst {
            MOperand::Reg(r) => {
                let old = self.cur(current, loc_of(r).unwrap(), span);
                uses.push(old);
                let v = self.def_reg(current, r, span, size, false, None);
                defs.push(v);
                (Operand::Value(v), Some(old))
            }
            MOperand::Mem(m) => {
                let mem = self.rewrite_mem(m, current, span);
                uses.extend(self.mem_uses(&mem));
                (Operand::Mem(mem), None)
            }
            other => (self.read_op(other, current, span), None),
        };
        let text = match (&place, lhs) {
            (Operand::Value(v), Some(old)) => {
                format!("{} = {} {} {}", self.vname(*v), mnemonic, ty_for_width(size), self.vname(old))
            }
            _ => format!("{} {} {}", mnemonic, ty_for_width(size), self.render_op(&place)),
        };
        (Op::Alu { op, dst: place, lhs, rhs: Operand::Imm(0), size }, text)
    }

    // -- helpers ------------------------------------------------------------

    fn push_value(
        &mut self,
        name: String,
        ty: Ty,
        home: Home,
        kind: ValueKind,
        span: Span,
        width: u32,
        partial: bool,
        const_value: Option<i64>,
    ) -> ValueId {
        let id = self.function.values.len() as ValueId;
        self.function.values.push(Value {
            id,
            name,
            ty,
            home,
            kind,
            def: None,
            span,
            bind: None,
            partial,
            width,
            const_value,
            undef: false,
        });
        id
    }

    fn new_slot(&mut self, span: Span) -> ValueId {
        let n = self.slot_versions;
        self.slot_versions += 1;
        self.push_value(
            format!("%slot{n}"),
            Ty::Ptr(Box::new(Ty::U8)),
            Home::Virtual,
            ValueKind::Slot,
            span,
            64,
            false,
            None,
        )
    }

    fn def_reg(
        &mut self,
        current: &mut HashMap<Loc, ValueId>,
        reg: &Reg,
        span: Span,
        width: u32,
        partial: bool,
        const_value: Option<i64>,
    ) -> ValueId {
        self.def_reg_ty(current, reg, ty_for_width_ty(width), span, width, partial, const_value)
    }

    fn def_reg_ty(
        &mut self,
        current: &mut HashMap<Loc, ValueId>,
        reg: &Reg,
        ty: Ty,
        span: Span,
        width: u32,
        partial: bool,
        const_value: Option<i64>,
    ) -> ValueId {
        let Some(loc) = loc_of(reg) else {
            return self.new_undef(Loc::Flags, span);
        };
        let base = match loc {
            Loc::Reg(b) => b,
            Loc::Flags => return self.def_flags(current, span),
        };
        let version = self.reg_versions.entry(base).or_insert(0);
        let name = format!("%{}.{}", reg64(base).name(), *version);
        *version += 1;
        let home = if base == GprBase::Sp {
            Home::Fixed(reg64(base), FixedKind::Stack)
        } else {
            Home::Pinned(reg64(base))
        };
        let kind = if base == GprBase::Sp { ValueKind::StackPtr } else { ValueKind::Reg };
        let ty = if base == GprBase::Sp {
            Ty::Ptr(Box::new(Ty::U8))
        } else {
            ty
        };
        let v = self.push_value(name, ty, home, kind, span, width, partial, const_value);
        current.insert(loc, v);
        v
    }

    fn def_flags(&mut self, current: &mut HashMap<Loc, ValueId>, span: Span) -> ValueId {
        let version = self.flags_versions;
        self.flags_versions += 1;
        let v = self.push_value(
            format!("%flags.{version}"),
            Ty::U64,
            Home::Virtual,
            ValueKind::Flags,
            span,
            64,
            false,
            None,
        );
        current.insert(Loc::Flags, v);
        v
    }

    fn cur(&mut self, current: &mut HashMap<Loc, ValueId>, loc: Loc, span: Span) -> ValueId {
        if let Some(v) = current.get(&loc) {
            *v
        } else {
            let v = self.new_undef(loc, span);
            current.insert(loc, v);
            v
        }
    }

    fn new_undef(&mut self, loc: Loc, span: Span) -> ValueId {
        let n = self.undef_versions;
        self.undef_versions += 1;
        let kind = match loc {
            Loc::Flags => ValueKind::Flags,
            Loc::Reg(GprBase::Sp) => ValueKind::StackPtr,
            Loc::Reg(_) => ValueKind::Reg,
        };
        let mut v = self.push_value(
            format!("%undef{n}"),
            Ty::U64,
            Home::Virtual,
            kind,
            span,
            64,
            false,
            None,
        );
        self.function.values[v as usize].undef = true;
        v
    }

    fn read_op(
        &mut self,
        o: &MOperand,
        current: &mut HashMap<Loc, ValueId>,
        span: Span,
    ) -> Operand {
        match o {
            MOperand::Reg(r) => match loc_of(r) {
                Some(loc) => Operand::Value(self.cur(current, loc, span)),
                None => Operand::Imm(0),
            },
            MOperand::Imm(i) => Operand::Imm(*i),
            MOperand::Sym { sym, add } => Operand::Sym { sym: *sym, add: *add },
            MOperand::Mem(m) => Operand::Mem(self.rewrite_mem(m, current, span)),
        }
    }

    fn rewrite_mem(
        &mut self,
        m: &MemOp,
        current: &mut HashMap<Loc, ValueId>,
        span: Span,
    ) -> Mem {
        let base = m.base.and_then(|r| {
            if r == Reg::Rip {
                None
            } else {
                loc_of(&r).map(|loc| self.cur(current, loc, span))
            }
        });
        let index = m
            .index
            .and_then(|r| loc_of(&r).map(|loc| self.cur(current, loc, span)));
        Mem {
            base,
            index,
            scale: m.scale,
            disp: m.disp.clone(),
            size: m.size,
            rip_relative: m.rip_relative || m.base == Some(Reg::Rip),
        }
    }

    fn operand_uses(&self, o: &Operand) -> Vec<ValueId> {
        match o {
            Operand::Value(v) => vec![*v],
            Operand::Mem(m) => self.mem_uses(m),
            _ => Vec::new(),
        }
    }

    fn mem_uses(&self, m: &Mem) -> Vec<ValueId> {
        let mut v = Vec::new();
        if let Some(b) = m.base {
            v.push(b);
        }
        if let Some(i) = m.index {
            v.push(i);
        }
        v
    }

    fn target_block(&self, label: usize) -> BlockId {
        self.cfg
            .label_block
            .get(&label)
            .copied()
            .unwrap_or(0) as BlockId
    }

    fn syscall_number(&self, _b: usize, flat: usize) -> Option<i64> {
        let mut j = flat;
        while j > 0 {
            j -= 1;
            match &self.body.insns[j].insn {
                Insn::Mov { dst: MOperand::Reg(r), src: MOperand::Imm(n), .. }
                    if loc_of(r) == Some(Loc::Reg(GprBase::A)) =>
                {
                    return Some(*n);
                }
                Insn::Mov { dst: MOperand::Reg(r), .. }
                    if loc_of(r) == Some(Loc::Reg(GprBase::A)) =>
                {
                    return None;
                }
                _ => {}
            }
        }
        None
    }

    fn syscall_name(&self, nr: i64) -> String {
        self.module
            .symbols
            .iter()
            .find(|s| s.syscall == Some(nr))
            .map(|s| s.name.clone())
            .unwrap_or_else(|| format!("syscall_{nr}"))
    }

    fn block_name(&self, b: BlockId) -> String {
        self.function.blocks[b as usize]
            .label
            .clone()
            .unwrap_or_else(|| format!("bb{b}"))
    }

    fn vname(&self, v: ValueId) -> String {
        self.function.values[v as usize].name.clone()
    }

    fn vty(&self, v: ValueId) -> String {
        ty_str(&self.function.values[v as usize].ty)
    }

    fn render_defs(&self, defs: &[ValueId]) -> String {
        defs.iter()
            .filter(|v| self.function.values[**v as usize].kind != ValueKind::Flags)
            .map(|v| self.vname(*v))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn render_op(&self, o: &Operand) -> String {
        match o {
            Operand::Value(v) => self.vname(*v),
            Operand::Imm(i) => render_imm(*i),
            Operand::Sym { sym, add } => {
                let name = self
                    .module
                    .symbols
                    .get(*sym)
                    .map(|s| s.name.clone())
                    .unwrap_or_else(|| format!("sym{sym}"));
                if *add == 0 {
                    format!("@{name}")
                } else {
                    format!("@{name}{add:+}")
                }
            }
            Operand::Mem(m) => self.render_mem(m),
        }
    }

    fn render_mem(&self, m: &Mem) -> String {
        let mut parts: Vec<String> = Vec::new();
        if m.rip_relative {
            parts.push("rip".to_string());
        }
        if let Some(b) = m.base {
            parts.push(self.vname(b));
        }
        if let Some(i) = m.index {
            if m.scale == 1 {
                parts.push(self.vname(i));
            } else {
                parts.push(format!("{}*{}", self.vname(i), m.scale));
            }
        }
        match &m.disp {
            Displacement::Const(0) => {}
            Displacement::Const(d) => parts.push(format!("{d}")),
            Displacement::Sym { sym, add } => {
                let name = self
                    .module
                    .symbols
                    .get(*sym)
                    .map(|s| s.name.clone())
                    .unwrap_or_else(|| format!("sym{sym}"));
                if *add == 0 {
                    parts.push(format!("@{name}"));
                } else {
                    parts.push(format!("@{name}{add:+}"));
                }
            }
        }
        format!("[{}]", parts.join(" + "))
    }
}

fn virt_unbind_inst(name: String, span: Span) -> Inst {
    Inst {
        op: Op::VirtUnbind { name: name.clone() },
        span,
        text: format!("virt unbind {name}"),
        defs: Vec::new(),
        uses: Vec::new(),
        effects: Effects::default(),
        machine: None,
        comment: None,
    }
}

fn is_plain_int(ty: &Ty) -> bool {
    matches!(
        ty,
        Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64 | Ty::Usize | Ty::Isize
    )
}

fn reg64(base: GprBase) -> Reg {
    Reg::Gpr { base, size: RegSize::R64 }
}

fn size_bits(size: u32, o: &MOperand) -> u32 {
    if size != 0 {
        return size;
    }
    match o {
        MOperand::Reg(r) => r.size().bits(),
        _ => 64,
    }
}

fn ty_for_width(width: u32) -> String {
    ty_str(&ty_for_width_ty(width))
}

fn ty_for_width_ty(width: u32) -> Ty {
    match width {
        8 => Ty::U8,
        16 => Ty::U16,
        32 => Ty::U32,
        _ => Ty::U64,
    }
}

fn render_imm(i: i64) -> String {
    if i < 0 {
        format!("-{}", -i)
    } else if i > 0xffff {
        format!("0x{i:x}")
    } else {
        i.to_string()
    }
}

fn flags_mask(f: FlagWrite) -> u8 {
    let mut m = 0;
    if f.cf {
        m |= 1;
    }
    if f.pf {
        m |= 2;
    }
    if f.af {
        m |= 4;
    }
    if f.zf {
        m |= 8;
    }
    if f.sf {
        m |= 16;
    }
    if f.of {
        m |= 32;
    }
    m
}

fn effects_of(insn: &Insn, ii: &InsnInfo) -> Effects {
    let mut e = Effects {
        reads_mem: ii.reads_mem,
        writes_mem: ii.writes_mem,
        writes_flags: flags_mask(ii.writes_flags),
        reads_flags: flags_mask(ii.reads_flags),
        stack_delta: ii.stack_delta,
        is_call: ii.is_call,
        is_noreturn: ii.is_noreturn,
        is_volatile: ii.is_volatile,
    };
    match insn {
        Insn::Push { .. } => e.stack_delta = -8,
        Insn::Pop { .. } => e.stack_delta = 8,
        Insn::StackSlot { grow } => e.stack_delta = if *grow { -8 } else { 8 },
        Insn::StackPad { pad } => e.stack_delta = -(*pad as i32),
        Insn::Call { contract, .. } => {
            e.stack_delta = 0;
            e.is_call = true;
            e.is_noreturn = contract.noreturn;
            e.writes_mem = true;
        }
        Insn::Syscall => {
            e.stack_delta = 0;
            e.is_call = true;
            e.writes_mem = true;
        }
        Insn::Volatile(_) => e.is_volatile = true,
        _ => {}
    }
    e
}

fn regs_str(regs: &[Reg]) -> String {
    regs.iter().map(|r| r.name()).collect::<Vec<_>>().join(", ")
}

/// Lift one function (exposed for tests/tools that already have a `FnBody`).
pub fn lift_function(module: &yana_codegen::Module, body: &FnBody) -> Function {
    let cfg = build_cfg(body);
    let dom = Dominators::new(&cfg);
    let live = Liveness::new(&cfg, body);
    let phi_locs = place_phis_with(&cfg, &live, &dom);
    let mut l = FnLifter::new(module, body, &cfg, &phi_locs);
    l.run(&dom);
    l.function
}

fn place_phis_with(cfg: &Cfg, live: &Liveness, dom: &Dominators) -> Vec<HashSet<Loc>> {
    let n = cfg.blocks.len();
    let mut phi_locs = vec![HashSet::new(); n];
    let mut def_blocks: HashMap<Loc, HashSet<usize>> = HashMap::new();
    for b in 0..n {
        if !cfg.reachable[b] {
            continue;
        }
        for &l in &live.def[b] {
            def_blocks.entry(l).or_default().insert(b);
        }
    }

    let mut work: VecDeque<(Loc, usize)> = VecDeque::new();
    for (l, blocks) in &def_blocks {
        for &b in blocks {
            work.push_back((*l, b));
        }
    }
    while let Some((l, b)) = work.pop_front() {
        for &d in &dom.df[b] {
            if d == 0 || !cfg.reachable[d] {
                continue;
            }
            if !live.live_in[d].contains(&l) {
                continue;
            }
            if phi_locs[d].insert(l) {
                work.push_back((l, d));
            }
        }
    }
    phi_locs
}
