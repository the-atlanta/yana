# Design notes — §12 atomics & volatile (feat/atomics, 30.10)

Implementation notes for the §12 draft. Binding decisions are recorded here so
they can be lifted into the spec later.

## Deviation from the spec's example: `lock add`, not `lock xadd`

SPEC §12 sketches `alt atomic(acqrel) @[p]: u64 += 1;` → `lock xadd` (x86) /
`ldaddal` (AArch64 LSE). The x86 side deviates deliberately:

- `xadd` **captures the old value into the source register** — it is
  `lock xadd [m], r` = `tmp = [m]; [m] += r; r = tmp`. Encoding `+=` as `xadd`
  would clobber a user-visible register invisibly, which violates §0 (visible
  expansion) and the "no hidden temporaries" iron rule.
- The language has no capture syntax (`x = atomic fetch_add(...)`), so there is
  nowhere to put the old value.
- `lock add` is the honest one-instruction expansion of `+=` under RMW
  semantics. When a capture syntax arrives, `xadd` becomes the right encoding
  for it.

Same reasoning applies on the AArch64 side (moot for now — atomics on
AArch64/Xtensa are rejected, see below).

## Other binding decisions

1. **Grammar.** `alt atomic(<order>) <place> <op>= <value>;` and
   `alt volatile <place> <op>=| <value>;`. Orders are NOT keywords: they parse
   as identifiers with exact text in {relaxed, acquire, release, acqrel,
   seqcst}; anything else → `atomic-order` diagnostic (syntax class, via a
   synthetic `BadAtomicOrder` token — same mechanism as the removed `pub`).
2. **AST.** `Stmt::Alt` gained a `modifier: AltModifier` field
   (`None | Atomic(AtomicOrder) | Volatile`). Single enum, spans kept on the
   statement as before.
3. **Semantics** (all semantic-class errors):
   - atomic target must be memory (`@[...]` or a static-bound name; a
     static-bound name is anonymous memory and needs no `mut`) → `atomic-register`
     if not;
   - source must be register or immediate → `atomic-src-memory` with help
     "load it into a register first" (no hidden temporaries, §0);
   - atomic `=` with immediate source → `atomic-assign-imm` with help "xchg
     needs a register source: bind the value first";
   - `*=` / `<<=` / `>>=` have no one-instruction atomic form → `atomic-op`;
   - non-x86-64 target → `unsupported-atomic-target` (owner decision 30.10:
     atomics on AArch64/Xtensa are not supported; LSE/LL/SC deferred).
4. **x86-64 mapping** (one statement = one instruction):
   - `=` → `xchg [m], r`. xchg with a memory operand is **implicitly locked** —
     no redundant `F0` prefix is emitted. seqcst plain-store semantics come
     free via xchg.
   - `+=` `lock add`, `-=` `lock sub`, `&=` `lock and`, `|=` `lock or`,
     `^=` `lock xor`, with reg or imm source. imm uses the imm8 form when it
     fits i8 (`F0 48 83 00 01`), else imm32/imm16/imm8 per size.
   - On x86 all five orders compile **identically** (lock RMW = full barrier).
     The order is recorded in the IR (`Insn::AtomicRMW { order }`) for future
     targets; no codegen difference.
5. **IR.** `Insn::AtomicRMW { op, dst, src, size, order }` with `AtomicOp ∈
   {Exchange, Add, Sub, And, Or, Xor}` and `MemOrder ∈ {Relaxed, Acquire,
   Release, AcqRel, SeqCst}`. Volatile: `Insn::Volatile(Box<Insn>)` —
   resolve lowers `alt volatile ...` to `Volatile(inner)`; backends encode the
   inner instruction unchanged.
6. **Instruction table.** AtomicRMW: reads = src regs + dst address regs;
   writes = none (register-wise — the memory cell is the destination);
   reads_mem = writes_mem = true; is_volatile = true; stack_delta 0; not
   terminator/call. writes_flags: Exchange → NONE (xchg doesn't touch flags),
   Add/Sub → ARITH, And/Or/Xor → LOGIC (same sets as their non-atomic
   counterparts). `Volatile(inner)` delegates to `insn_info(inner)` with
   `is_volatile = true`.
7. **iced backend.** iced-x86 1.21 `Instruction::set_has_lock_prefix(true)` is
   used (checked first in the registry sources — it exists, so no raw 0xF0
   byte insertion is needed; the prefix is counted by the encoder itself in
   both the sizing sweep and the real encode). xchg uses the existing
   `xchg_code()` table (Xchg_rm64_r64 / rm32 / rm16 / rm8 — verified names in
   iced's code.rs).
   - **Encoding fixup subtlety**: the rip-relative disp32 fixup pass assumed
     the displacement field is the LAST 4 bytes of the instruction. That holds
     for the pre-§12 instruction set but not for `lock add [rel sym], imm` —
     the imm8/imm32 trails the disp32. AtomicRMW now gets its own fixup arm
     that skips the trailing immediate (`atomic_trailing_imm` mirrors the
     encoding choice).
8. **NASM backend.** `lock add qword [p], 1` — the size qualifier
   (qword/dword/word/byte) is always emitted for atomic memory operands
   (required for memory+imm; harmless elsewhere). `xchg qword [p], rax`
   without lock. Volatile emits the inner text unchanged. Oracle verified:
   `yana oracle examples/atomics.yana` → MATCH.
9. **LSP.** knowledge.rs: `atomic`/`volatile` keyword entries with snippet
   inserts (order names via a snippet enum), `atomic_orders()` completion
   list, `ATOMIC_HOVER`/`VOLATILE_HOVER` §12 summaries. One contiguous hunk.
10. **`@[...]` notation.** SPEC §3 writes anonymous memory as
    `@[rbx + rcx*8 + 16]: u64`, but the grammar only accepted the bare
    `[addr]` form in place position. `PlaceTyped` now accepts an optional
    leading `@` for `[addr]` places, so the spec's `@[p]: u64` parses; the
    bare form remains valid (and is what `bind x @ [arr + i*8]` etc. used all
    along).

## Examples

`examples/atomics.yana`: three `alt atomic(relaxed) @[counter]: u64 += N;`
ops on a `.data` static, then loads the counter and exits with it.
`yana run examples/atomics.yana` → exit code 12 (= 3+4+5). Oracle MATCH.
