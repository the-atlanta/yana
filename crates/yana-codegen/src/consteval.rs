//! Build-time evaluation (§8): values only — integers, booleans, arrays,
//! tuples, `if`-expressions, `const fn` calls with recursion. No memory, no
//! registers, no side effects, no floats. Overflow is an error; a step budget
//! bounds runaway recursion.

use std::collections::HashMap;

use yana_ast::{ConstBinOp, ConstExpr, ConstFnItem, ConstUnOp, Diagnostic, DiagCode, Span};

/// A build-time value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i128),
    Bool(bool),
    Array(Vec<Value>),
    Tuple(Vec<Value>),
}

impl Value {
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Bool(b) => Some(*b as i128),
            _ => None,
        }
    }

    /// Flatten to bytes little-endian, for static data initializers.
    pub fn to_bytes(&self, elem_size: usize) -> Vec<u8> {
        match self {
            Value::Int(i) => (i.to_le_bytes()[..elem_size.min(16)]).to_vec(),
            Value::Bool(b) => vec![*b as u8],
            Value::Array(items) | Value::Tuple(items) => {
                items.iter().flat_map(|v| v.to_bytes(elem_size)).collect()
            }
        }
    }
}

/// Environment for evaluation: consts, const fns, and call parameters.
pub struct ConstEnv<'a> {
    pub consts: HashMap<String, Value>,
    pub fns: HashMap<String, &'a ConstFnItem>,
    /// Evaluation-step budget (§8 🟡).
    pub step_budget: u64,
    steps_used: u64,
}

impl<'a> ConstEnv<'a> {
    pub fn new() -> Self {
        ConstEnv { consts: HashMap::new(), fns: HashMap::new(), step_budget: 1_000_000, steps_used: 0 }
    }

    /// Build an env with a given const/fn set and step budget.
    pub fn with(
        consts: HashMap<String, Value>,
        fns: HashMap<String, &'a ConstFnItem>,
        step_budget: u64,
    ) -> Self {
        ConstEnv { consts, fns, step_budget, steps_used: 0 }
    }
}

impl Default for ConstEnv<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Evaluation error — always converted to a diagnostic by the caller.
#[derive(Debug)]
pub enum ConstError {
    /// Message + span.
    Msg(String, Span),
}

impl ConstError {
    pub fn into_diag(self) -> Diagnostic {
        match self {
            ConstError::Msg(m, span) => Diagnostic::error(DiagCode::Semantic, "const-eval", m, span),
        }
    }
}

pub type ConstResult<T> = Result<T, ConstError>;

/// Evaluate a const expression.
pub fn eval(env: &mut ConstEnv, expr: &ConstExpr, locals: &HashMap<String, Value>) -> ConstResult<Value> {
    env.steps_used += 1;
    if env.steps_used > env.step_budget {
        return Err(ConstError::Msg(
            "const evaluation exceeded the step budget (runaway recursion?)".into(),
            Span::DUMMY,
        ));
    }

    match expr {
        ConstExpr::Int { value, .. } => Ok(Value::Int(*value)),
        ConstExpr::Bool { value, .. } => Ok(Value::Bool(*value)),
        ConstExpr::Name { name, span } => {
            if let Some(v) = locals.get(name) {
                return Ok(v.clone());
            }
            if let Some(v) = env.consts.get(name) {
                return Ok(v.clone());
            }
            Err(ConstError::Msg(format!("unknown const name `{name}`"), *span))
        }
        ConstExpr::Array { items, span } => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(eval(env, it, locals)?);
            }
            let _ = span;
            Ok(Value::Array(out))
        }
        ConstExpr::Tuple { items, span } => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(eval(env, it, locals)?);
            }
            let _ = span;
            Ok(Value::Tuple(out))
        }
        ConstExpr::Repeat { value, count, span } => {
            let v = eval(env, value, locals)?;
            let n = eval(env, count, locals)?.as_int().ok_or_else(|| {
                ConstError::Msg("repeat count must be an integer".into(), *span)
            })?;
            if n < 0 || n > 1 << 20 {
                return Err(ConstError::Msg(
                    format!("repeat count {n} out of range (0..=1M)"),
                    *span,
                ));
            }
            Ok(Value::Array(vec![v; n as usize]))
        }
        ConstExpr::If { cond, then_b, else_b, .. } => {
            let c = eval(env, cond, locals)?;
            match c {
                Value::Bool(true) | Value::Int(1..) => eval(env, then_b, locals),
                Value::Bool(false) | Value::Int(0) => eval(env, else_b, locals),
                Value::Int(_) => eval(env, else_b, locals),
                _ => Err(ConstError::Msg("if condition must be boolean".into(), Span::DUMMY)),
            }
        }
        ConstExpr::Unary { op, expr, span } => {
            let v = eval(env, expr, locals)?;
            match op {
                ConstUnOp::Neg => {
                    let i = v.as_int().ok_or_else(|| ConstError::Msg("neg on non-int".into(), *span))?;
                    i.checked_neg()
                        .map(Value::Int)
                        .ok_or_else(|| ConstError::Msg("const overflow in negation (§8: overflow is an error)".into(), *span))
                }
                ConstUnOp::Not => match v {
                    Value::Bool(b) => Ok(Value::Bool(!b)),
                    Value::Int(i) => Ok(Value::Int(!i)),
                    _ => Err(ConstError::Msg("not on non-scalar".into(), *span)),
                },
            }
        }
        ConstExpr::Binary { op, lhs, rhs, span } => {
            let l = eval(env, lhs, locals)?;
            let r = eval(env, rhs, locals)?;
            binary(*op, l, r, *span)
        }
        ConstExpr::Call { name, args, span } => {
            let f = env.fns.get(name).copied().ok_or_else(|| {
                ConstError::Msg(format!("unknown const fn `{name}`"), *span)
            })?;
            if args.len() != f.params.len() {
                return Err(ConstError::Msg(
                    format!("`{name}` takes {} args, got {}", f.params.len(), args.len()),
                    *span,
                ));
            }
            let mut call_locals = HashMap::new();
            for ((pname, _), arg) in f.params.iter().zip(args) {
                call_locals.insert(pname.clone(), eval(env, arg, locals)?);
            }
            eval(env, &f.body, &call_locals)
        }
    }
}

fn binary(op: ConstBinOp, l: Value, r: Value, span: Span) -> ConstResult<Value> {
    // boolean ops
    if matches!(op, ConstBinOp::And | ConstBinOp::Or) {
        let a = as_bool(&l, span)?;
        let b = as_bool(&r, span)?;
        return Ok(Value::Bool(match op {
            ConstBinOp::And => a && b,
            ConstBinOp::Or => a || b,
            _ => unreachable!(),
        }));
    }
    // comparison ops
    if matches!(op, ConstBinOp::Eq | ConstBinOp::Ne | ConstBinOp::Lt | ConstBinOp::Le | ConstBinOp::Gt | ConstBinOp::Ge) {
        return match (&l, &r) {
            (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(cmp_bool(op, *a, *b))),
            _ => {
                let a = l.as_int().ok_or_else(|| ConstError::Msg("compare on non-scalar".into(), span))?;
                let b = r.as_int().ok_or_else(|| ConstError::Msg("compare on non-scalar".into(), span))?;
                Ok(Value::Bool(cmp_int(op, a, b)))
            }
        };
    }
    // arithmetic/bit ops on ints
    let a = l.as_int().ok_or_else(|| ConstError::Msg("arithmetic on non-scalar".into(), span))?;
    let b = r.as_int().ok_or_else(|| ConstError::Msg("arithmetic on non-scalar".into(), span))?;
    let overflow = || {
        ConstError::Msg(
            "const overflow (§8: overflow is an error; wrapping must be explicit)".into(),
            span,
        )
    };
    let v = match op {
        ConstBinOp::Add => a.checked_add(b).ok_or_else(overflow)?,
        ConstBinOp::Sub => a.checked_sub(b).ok_or_else(overflow)?,
        ConstBinOp::Mul => a.checked_mul(b).ok_or_else(overflow)?,
        ConstBinOp::Div => {
            if b == 0 {
                return Err(ConstError::Msg("division by zero in const expression".into(), span));
            }
            a.checked_div(b).ok_or_else(overflow)?
        }
        ConstBinOp::Rem => {
            if b == 0 {
                return Err(ConstError::Msg("modulo by zero in const expression".into(), span));
            }
            a.checked_rem(b).ok_or_else(overflow)?
        }
        ConstBinOp::BitAnd => a & b,
        ConstBinOp::BitOr => a | b,
        ConstBinOp::BitXor => a ^ b,
        ConstBinOp::Shl | ConstBinOp::Shr => {
            if !(0..128).contains(&b) {
                return Err(ConstError::Msg(format!("shift amount {b} out of range 0..128"), span));
            }
            if op == ConstBinOp::Shl {
                a.checked_shl(b as u32).ok_or_else(overflow)?
            } else {
                a.checked_shr(b as u32).ok_or_else(overflow)?
            }
        }
        _ => unreachable!(),
    };
    Ok(Value::Int(v))
}

fn as_bool(v: &Value, span: Span) -> ConstResult<bool> {
    match v {
        Value::Bool(b) => Ok(*b),
        Value::Int(0) => Ok(false),
        Value::Int(_) => Ok(true),
        _ => Err(ConstError::Msg("expected boolean".into(), span)),
    }
}

fn cmp_bool(op: ConstBinOp, a: bool, b: bool) -> bool {
    match op {
        ConstBinOp::Eq => a == b,
        ConstBinOp::Ne => a != b,
        ConstBinOp::Lt => !a && b,
        ConstBinOp::Le => !a || b,
        ConstBinOp::Gt => a && !b,
        ConstBinOp::Ge => a || !b,
        _ => unreachable!(),
    }
}

fn cmp_int(op: ConstBinOp, a: i128, b: i128) -> bool {
    match op {
        ConstBinOp::Eq => a == b,
        ConstBinOp::Ne => a != b,
        ConstBinOp::Lt => a < b,
        ConstBinOp::Le => a <= b,
        ConstBinOp::Gt => a > b,
        ConstBinOp::Ge => a >= b,
        _ => unreachable!(),
    }
}
