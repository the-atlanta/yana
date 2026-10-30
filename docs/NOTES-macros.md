# NOTES — §9 macros (implementation record)

Design decisions made while implementing SPEC §9 that go beyond the spec text.
The branch owner (hermes) brief + these notes are the authority for the code in
`crates/yana-parser/src/macros.rs`.

## Architecture

- **Token-level pre-pass inside `yana_parser::parse()`** (`src/macros.rs`,
  `expand(triples) -> ExpandOutput`), after lexing, before LALRPOP. The grammar
  never sees `macro`/`macro_rules` declarations or invocation sites — they are
  gone from the stream by parse time. This is SPEC §14 pass 0.5 made concrete.
- Expansion loops to a fixpoint (invocations may produce invocations), with a
  64-pass depth limit → `macro-recursion-limit`.
- Bodies are captured as balanced token trees; matching is structural, never
  semantic. Pure substitution — no evaluation (§9, §0.2).

## Key decisions

1. **Invocation consumes its trailing `;`.** Rust-style: `set!(x, 42);` — the
   `!`-invocation *including* its terminating semicolon is replaced by the
   expansion. Rationale: a macro body ends in `;` per statement; if the site's
   `;` survived we'd get `;;` (double Semi → parse error). Consequence: in NASM
   output an invocation looks like the expansion itself, no stray separator.
2. **Fragment matching**: `ident` = exactly one Ident; `label` = exactly one
   LabelRef; `block` = one balanced `{ ... }` tree; `place`/`value`/`type` =
   greedy balanced slice up to the next pattern literal at bracket-depth 0.
   Slice syntax correctness is enforced naturally when the expansion re-parses.
3. **Repetition capture lists are per-metavariable-per-repetition.**
   `$( $a:ident, $b:ident ),*` stores separate lists for `a` and `b`; expansion
   iterates them in lockstep. Equal lengths required → `macro-repeat-mismatch`.
   (First implementation flat-concatenated captures — wrong for multi-var
   repetitions; rewritten.)
4. **Hygiene**: at definition time the body tree is scanned for declared names —
   `bind [mut] <ident>` (incl. destructuring `<ident> @`), `label (<ident>)`.
   At each expansion, every occurrence (declaration and reference) of those
   names in the *template* is renamed to `<name>__h<N>` (N = global expansion
   counter). Captured call-site fragments splice verbatim, never renamed.
   Free label references (undeclared in the body, e.g. `'done` jumping to an
   enclosing label) are deliberately NOT renamed — they resolve against the
   enclosing scope. Edge case: a free ref to a name that *happens* to equal a
   declared name in another expansion is impossible because declared names are
   renamed away at every expansion.
5. **Expansion comments**: `macro \`name\` → #N` is injected into the
   file-level comments channel (`ParseOutput.comments`, offset = invocation
   site). Known limitation: comments ride the *file* channel — the NASM backend
   prints file-level comments at the top of the output, not per-instruction.
   Per-instruction attachment via `SpannedInsn.comment` would need synthetic
   spans inside the expansion (post-merge improvement candidate).
6. **Item position**: invocations are statement-position only (§9 deferred
   item-macros). Detection: brace-depth heuristic during the scan — an
   invocation at depth 0 → `macro-item-position`.
7. **Diagnostics** (all carry spans, all flow through `ParseOutput.diagnostics`):
   `unknown-macro` (with "did you mean" suggestions), `macro-arity` (positional
   count / named missing-duplicate-unknown), `macro-match` (no macro_rules arm),
   `macro-recursion-limit`, `macro-repeat-mismatch`, `macro-item-position`,
   `macro-syntax` (unbalanced body).
8. **Lexer**: new `Token::Dollar` (`$`). `bad_byte_recorded_not_fatal` updated —
   `$` is now a valid byte, previously a lex error.
9. **CLI**: `yana expand --macros <file>` prints the post-expansion token
   stream (`lo..hi<TAB>kind<TAB>text` per line, comments interleaved by
   offset). Default `expand` (resolved IR dump) unchanged.
10. **LSP**: `macro` / `macro_rules!` completion items + hover docs (§9),
    plus `align` completion that was missing. One contiguous hunk in
    `knowledge.rs` to keep merges with parallel branches clean.

## Dependency on master

Requires the label-body scoping fix (`50bccd6`): hygiene-renamed binds in two
expansions of the same macro would otherwise trip `reg-conflict` because label
bodies shared the enclosing scope. Merged master into feat/macros before tests.

## Tests

- `crates/yana-parser/tests/macros.rs` — 16 tests: both declaration forms,
  positional/named invocation, fragments, `$(...),*`/`$(...),+` lockstep
  (incl. two metavariables in one repetition and zero-match), hygiene
  (distinct symbols per expansion, free labels untouched), all six error kinds,
  expansion comment in the comments channel, declaration removal.
- `crates/yana-cli/tests/macros_e2e.rs` — 4 tests: expansion → resolve →
  assemble → disassemble (`mov`/`add` present), repetition assembles,
  NASM emit carries the expansion comment, hygiene program resolves with
  `top__h1`/`top__h2` label defs.
