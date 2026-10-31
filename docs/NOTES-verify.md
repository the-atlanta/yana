# NOTES-verify — §14 pass 4 (`--verify`): intervals + minimal SMT contracts

Owner decision (SPEC §15 ✅ 30.10): intervals + MINIMAL contracts —
requires/ensures over integer param/result values, SMT via z3.
Memory model: CONSERVATIVE — any memory write kills ALL memory facts.

Branch `feat/verify`, forked from master f9824e3. Never push.

## Plan / milestones (commit at each)

1. This plan doc.
2. AST + grammar + parse tests: `Contracts { requires: Vec<Sp<ConstExpr>>,
   ensures: Vec<Sp<ConstExpr>> }` in yana-ast; `ContractClause` grammar rule
   (`requires <expr>;` / `ensures <expr>;`) after ClobbersOpt, before body;
   attach to FnItem (and ExternFnItem — clauses on externs are accepted and
   validated but not checked, see deviations).
3. Resolve plumbing: collect contracts into FnBody (new fields:
   `contracts: ContractsIr` — lowered ConstExpr kept as yana_ast::ConstExpr
   clones + param/result name lists); validate idents against signature →
   `verify-contract-name` error at resolve time.
4. verify.rs: interval domain + fixed-point + div-zero check + unit tests.
5. z3 emitter + contract checks (call-site requires / exit ensures) + tests.
6. CLI: `yana verify <file>` subcommand + `--verify` flag on build; e2e tests.
7. LSP knowledge hunk + examples/verify.yana + full gates.

## Architecture

- `crates/yana-analysis/src/verify.rs`, exported from lib.rs. Pass 4 is
  READ-ONLY over the resolved Module — it must NOT rewrite the IR (unlike
  analyze() which lowers StackAlign in place). Pipeline per body:
  resolve_module → cfg::build → interval fixed-point → contract checks →
  Vec<Diagnostic>.
- CLI drives: `verify` = resolve (+ pass 3 analyze for clobbers? NO — see
  deviation D3) → yana_analysis::verify::verify(&module) → report::render;
  exit = count of error-level verify diagnostics.

## Interval domain (per binding decision #2)

- Per-register interval [lo, hi] as i128; TOP = (i128::MIN, i128::MAX);
  BOTTOM = (1, 0) (lo > hi). State: HashMap<Reg, Interval> keyed by exact
  Reg (sizes normalized to R64 family member when writing facts; reads
  consult the R64 alias of the register and fall back to TOP if the exact
  sub-register differs — see D1). Plus one bool `memory_known` flag: statics'
  initial const values are the only memory facts; any writes_mem insn (incl.
  Push, Call, Syscall, AtomicRMW, Volatile-of-write) kills them → all memory
  reads afterwards give TOP.
- Worklist fixed-point over cfg blocks in RPO; join at block entry = widening
  hull (min lo, max hi) — monotone, terminates.
- Transfers per Insn variant (values), reads/writes via insn_info():
  - Mov imm → point; Mov reg → copy; Mov mem-src → TOP for dst (and memory
    facts only used for static sym disp with known init value before any
    kill — keep simple: memory read → TOP always; D2).
  - Add/Sub → interval add/sub saturating at i128 bounds.
  - Imul2/MulWide → hull of 4 corner products (saturating); MulWide writes
    both pair regs → both TOP? No: low half = saturating mul hull, high TOP.
    Keep simple+sound: pair result regs → TOP; Imul2 dst → corner hull.
  - And dst, imm → [0, mask] (mask = imm value); And reg → TOP-ish hull of
    operands per decision: [0, max(2^bits-1)]. Or/Xor → hull [0, 2^bits-1].
  - Shl/Shr by const → shift bounds (saturating; Shr unsigned clamps lo≥0);
    by interval → hull with bitlen bound ([0, 2^bits-1] for Shr; shl →
    saturating corner shifts over shift-interval endpoints clamped [0,bits)).
  - Movzx → clamp source into [0, 2^src_bits-1] then fit dst; Movsx → clamp
    into [-2^(n-1), 2^(n-1)-1]. `as` truncation: resolver already lowered to
    resized reg operand + Mov; at Mov with size<64 apply clamp by dst reg
    signedness unknown → conservative: Mov into 32-bit reg zero-extends in
    hw? NOT in YANA semantics — treat sub-64 writes as: clamp value to
    [-2^63..] per size bits signed OR unsigned hull: use
    [-(2^(n-1)), 2^n-1] hull (sound both ways); D1 note.
  - DivWide → div-by-zero check (#3), then quot/rem bounds simple+sound:
    rem ∈ (-|d|, |d|) hull [-(dm-1), dm-1] where dm = max|divisor|; quot:
    dividend bounds (rdx:rax pair unknown → TOP) → quot TOP unless dividend
    point-known. Keep: divisor known nonzero → no diag; results TOP
    (rem interval refinement only when both pair and divisor are points).
  - Cmp + Jcc: remember (a-interval, b-interval, cc) from the Cmp preceding
    each Jcc (resolver emits them adjacently); on the TAKEN edge refine with
    the six signed ccs (L/Le/G/Ge/E/Ne); NOT-taken edge gets negation.
    Unsigned ccs (B/Be/A/Ae) refine as unsigned (clamp lo≥0) — same math
    on values known ≥0; if operand interval crosses 0 for unsigned cc,
    skip refinement (sound). Flag-only Jcc (S/Ns/O/...): no refinement.
  - Call: clobbers → TOP; results → TOP; rsp untouched value-wise;
    memory facts killed (writes_mem). Syscall: kill rax/rcx/r11 → TOP,
    memory facts killed. (insn_info(Syscall).writes already lists rax/rcx/r11.)
  - AtomicRMW: no reg dst; memory kill. Volatile(inner): delegate + memory
    kill if inner writes_mem.
  - Lea/LeaSym → TOP (addresses). Neg → negate+swap bounds. Inc/Dec → ±1.
    Not → TOP (bitwise, conservative). Xchg a,b → swap intervals.
    Pop dst → TOP + memory kill? Pop reads stack memory — stack is not
    tracked as "memory facts" beyond statics; D2: Pop → TOP for dst, no
    global kill (push/pop are balanced locals; still sound because we never
    claim facts about stack cells). Push → writes_mem → kills statics facts.
    (Conservative per owner decision: any memory write kills memory facts.
    Push IS a memory write → kill. Pop reads memory → dst TOP.)
  - ExtendPair signed → rdx = sign hull of rax; unsigned → rdx = [0,0] if
    rax ≥ 0 known else [0, 2^31...] simple: rdx = 0 point when unsigned
    (xor edx,edx), rdx = hull(-1,0) when signed and rax interval crosses 0,
    else point sign.
  - StackPad/StackSlot/StackAlign/Nop/Int3/Ret/Jmp: no value facts (rsp
    excluded from tracking — never bind facts to rsp).

## Div-by-zero (#3, flagship diagnostic)

For every DivWide insn: divisor interval contains 0 → error
`verify-div-zero` (DiagCode::Semantic), message includes divisor interval +
insn span. Excludes 0 → OK (+ simple sound quotient/remainder bounds).
Note: resolver already rejects CONST zero divisors (`div-zero` at resolve);
pass 4 catches the flow-dependent cases.

## Contracts (#4–#6)

- Syntax: `requires <expr>;` / `ensures <expr>;` clauses on fn items, after
  the optional `clobbers:` block, before the body. KwRequires/KwEnsures
  already in lexer + grammar extern block. New rule `ContractClause` reusing
  the ConstExpr chain; new AST struct `Contracts { requires: Vec<Sp<ConstExpr>>,
  ensures: Vec<Sp<ConstExpr>> }` on FnItem/ExternFnItem.
- Idents: in requires/ensures an ident names a PARAMETER; in ensures idents
  may ALSO name result regs from ret_sig (binding name if `-> (lo @ rax…)`
  else the register name, e.g. `rax`). Unknown ident → `verify-contract-name`
  at resolve time.
- Resolve stores contracts in FnBody (new field `contracts`), plus the
  param-name → reg map and result reg names, so the verifier can look them
  up by symbol index. Imported (§10) fn contracts: OUT OF SCOPE (D4).
- Checks via z3 (`/home/nika/.local/bin/z3` or PATH `z3`, v5.3.3,
  std::process::Command, 5s timeout; missing/timeout → ONE warning
  `verify-smt-unavailable` per verify run, SKIP contract checks, never fail):
  a. CALL-SITE requires: at every Call insn, per requires clause of callee:
     Int var per param; assert caller's interval facts for ACTUAL args at the
     call point ((and (>= v lo) (<= v hi)); TOP → unconstrained); assert
     NOT(requires); check-sat. sat → error `verify-requires` (Contract code,
     Error level per D5) with counterexample model in the message; unsat →
     proven.
  b. EXIT ensures: per Ret insn AND fall-through end (if !returns_never),
     per ensures clause: Int vars for params (ENTRY intervals — from
     signature; unknown → unconstrained) and result regs (intervals at exit
     point); assert NOT(ensures); sat → error `verify-ensures` + model.
- SMT-LIB2 emitter: (set-logic QF_NIA), (declare-const v_name Int),
  (assert ...), (check-sat), (get-value (...)). ConstExpr → SMT: Name →
  v_-prefixed var, Int → literal, Bool → true/false, binary arith/cmp/&&/||
  → SMT ops, unary Neg → (- x), Not → (not x). Unsupported shapes (If/Call/
  Array/Tuple/Repeat) → skip check with `verify-smt-unavailable`-style note?
  No: they're const-evaluable — pre-evaluate constant subtrees via consteval
  when no idents; otherwise emit error `verify-contract-expr` (D6).

## CLI (#7)

- `yana verify <file>`: load → parse → resolve (strict=false) → if resolve
  clean, run verify::verify(&module) → render → exit = error count.
- `yana build --verify`: after pass 3 analyze, run pass 4; errors fail build.
- LSP knowledge.rs: add requires/ensures Items to keywords() (remove from
  reserved() list) + hover — ONE contiguous hunk.

## Deviations / extra decisions (recorded per brief)

- D1: register keys normalized to R64 family member; sub-register writes
  (e.g. eax) invalidate the whole R64 fact then rebind with size-clamped
  interval: write to R32 → value ∈ [0, 2^32-1] (x86 zero-extends) intersected
  with src interval; R16/R8 writes → R64 fact = TOP (partial update unsound
  to model precisely; conservative).
- D2: memory facts = ONLY static .rodata/.data symbols' initial constant
  bytes, read via Mov from Sym-displacement MemOp with base/index None;
  killed by ANY writes_mem insn (incl. Push/Call/Syscall/AtomicRMW). Memory
  reads with unknown contents → dst TOP. Pop → dst TOP, no kill (stack slots
  never carry tracked facts).
- D3: `yana verify` does NOT run pass 3 analyze() (keeps pass 4 read-only);
  Call contracts at verify time carry the resolver's conservative clobbers
  (explicit block or empty for local fns) — sound: unlisted clobbers just
  leave stale facts... UNSOUND. Fix: pass 4 kills ALL caller-saved regs
  (SysV: rax rcx rdx rsi rdi r8-r11) at every Call in addition to declared
  clobbers/results. That's the conservative ABI assumption and keeps verify
  independent of pass 3. `build --verify` runs after analyze, where symbols
  carry derived clobbers — same rule applies, just tighter.
- D4: imported fn contracts out of scope (§10 ImportedDecl carries no
  contracts; loader unchanged).
- D5: `verify-requires`/`verify-ensures` use DiagCode::Contract but are
  emitted at Error level directly (spec §11 contract class is warning by
  default — but a PROVEN contract violation is a bug, not a style issue;
  owner brief says "error `verify-requires` (DiagCode::Contract)").
- D6: unsupported ConstExpr shapes in contracts (If/Call/Array/Tuple/Repeat
  that don't const-fold) → resolve-time error `verify-contract-expr`.
- D7: `ensures` idents may name result regs by binding name (ret_sig tuple
  part names) or bare reg name ("rax"); both map to the R64 reg.
- D8: ensures at fall-through end checked only when !returns_never and the
  end is reachable (last block has fallthrough — cfg models it; simply:
  state at end of last insn index if reachable in fixed-point).
- D9: bitwise ConstExpr ops (`&`, `|`, `^`) have NO QF_NIA encoding (SMT
  Ints are unbounded integers, not bitvectors). smt_of returns None for
  them → the affected clause is skipped with a `verify-contract-expr`
  WARNING (not an error — it's a limitation, not a violation). Shifts by a
  CONST operand DO encode (shl→×2^k, shr→div 2^k); shifts by a variable
  return None. Keep contract expressions to + - * / % comparisons && ||
  and unary -/! on parameters/results.
- D10: the contract VISITOR runs on the PRE-instruction state (visit before
  xfer in walk_block). A Call kills all caller-saved regs — visiting after
  the transfer would erase exactly the actual-argument interval facts the
  call-site `requires` check needs. Ret visits the state at the return point
  (rax holds the result there), which is correct for `ensures`.

## Status (attempt #6 — COMPLETE)

Milestones 1–7 all done and committed on feat/verify:
- 4 (9c96c6d): wired `pub mod verify;`, fixed compile errors (SpannedInsn
  is in yana_codegen::ir; Operand::Imm not a dst; Option<&mut> borrows not
  moves; clone taken-edge state), visit-before-xfer fix, extract_value
  balanced-paren scan for negative z3 models ((- 5)); 10 unit tests
  (interval arithmetic corners + i128 saturation + BOTTOM; hull/intersect/
  exclude_point; div-zero detected, NOT flagged when guarded / const-folded
  / arith-derived; widening fixed point terminates on a loop; smt_of shapes).
- 5 (57bc999): verify_with(module, z3) split + 8 z3-gated contract
  integration tests (requires violated by imm 0 with counterexample model,
  proven by imm/interval, unprovable via a branch-join interval; ensures
  satisfied vs violated; verify-smt-unavailable warns once, skips, never
  fails). Label pitfall: `call`/`zero` are keywords — test labels renamed.
- 6 (b5e64fa): `yana verify <file>` subcommand (resolve w/o pass 3 per D3 →
  verify → render → exit=error count) + `build --verify` (pass 4 after
  analyze; errors fail the build, single-file AND §10 multi-module via
  loader_verify). tests/verify_e2e.rs: 7 e2e tests.
- 7 (97fec70): knowledge.rs requires/ensures promoted reserved()→keywords()
  with completion snippets + hover; examples/verify.yana demo.

Gates (all green, ukko, z3 5.3.3): workspace tests 144 pass (111 master +
25 new + 8 pre-existing on branch); oracle MATCH on hello/factorial/atomics
/verify (8/10/7/18 insns); hello prints "Hello, YANA!"; factorial exits
120; atomics exits 12; verify.yana verifies clean (exit 0) and runs (exit
100). LSP smoke PASS (completion+hover intact).

## Gates

- RUSTFLAGS="-A warnings" cargo test -q --workspace: baseline 111 green.
- oracle MATCH ×3 (hello, factorial, atomics); hello runs; factorial exit
  120; atomics exit 12. Never build in /tmp. Commit after every milestone.
