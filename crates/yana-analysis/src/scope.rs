//! Label scope rules (§6).
//!
//! "Переход на соседние метки и наружу из вложенных блоков можно. Внутрь
//! вложенного блока нельзя." A branch is legal when its target label was
//! declared at a lexical depth ≤ the branch's depth. Jumping *into* a deeper
//! block (target depth > branch depth) is an error.

use yana_ast::{DiagCode, Diagnostic};
use yana_codegen::{FnBody, Module};

use crate::cfg::Cfg;

pub fn check(module: &Module, body: &FnBody, _cfg: &Cfg) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let fn_name = module.symbols.get(body.symbol).map(|s| s.name.as_str()).unwrap_or("?");

    for br in &body.branches {
        let Some(def) = body.label_defs.get(br.label) else { continue };
        if def.scope_depth > br.scope_depth {
            diags.push(
                Diagnostic::error(
                    DiagCode::Semantic,
                    "label-into-block",
                    format!(
                        "cannot branch into the nested block of label '{}' from `{fn_name}` (§6: jumping inward is illegal)",
                        def.name
                    ),
                    br.span,
                )
                .with_help("branch to a label declared at the same or an outer block level"),
            );
        }
    }

    diags
}
