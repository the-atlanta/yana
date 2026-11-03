//! Debug Adapter Protocol server for YANA.
//!
//! Started as `yana-lsp --dap`. DAP is a separate protocol from LSP (same
//! stdio framing idea, different message shape), so it lives in its own mode
//! of the same binary.
//!
//! Because YANA compiles to a small explicit IR where every instruction keeps
//! its source span, the adapter can *interpret* the IR directly — no DWARF,
//! no ptrace, no compiled executable. That gives line breakpoints, stepping,
//! stack traces, register/stack/flags inspection and `evaluate` for free.
//!
//! Supported requests: `initialize`, `launch`/`attach`, `setBreakpoints`,
//! `configurationDone`, `threads`, `stackTrace`, `scopes`, `variables`,
//! `evaluate`, `setVariable`, `continue`, `next`, `stepIn`, `stepOut`,
//! `pause`, `source`, `modules`, `loadedSources`, `setBreakpointLocations`,
//! `disconnect`, `terminate`.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use yana_ast::reg::{GprBase, Reg, RegSize};

use crate::vm::{RunMode, RunOutcome, Vm};

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

struct Transport {
    reader: BufReader<std::io::Stdin>,
    writer: std::io::Stdout,
    seq: i64,
}

impl Transport {
    fn new() -> Self {
        Transport {
            reader: BufReader::new(std::io::stdin()),
            writer: std::io::stdout(),
            seq: 1,
        }
    }

    /// Read one `Content-Length`-framed JSON message.
    fn read_message(&mut self) -> std::io::Result<Option<Value>> {
        let mut content_length: Option<usize> = None;
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 {
                return Ok(None);
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some(rest) = trimmed.strip_prefix("Content-Length:") {
                content_length = rest.trim().parse().ok();
            }
            // Other headers (Content-Type) are ignored.
        }
        let Some(len) = content_length else {
            return Ok(None);
        };
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
        Ok(serde_json::from_slice(&buf).ok())
    }

    fn send(&mut self, mut msg: Value) {
        msg["seq"] = json!(self.seq);
        self.seq += 1;
        let body = msg.to_string();
        let _ = write!(self.writer, "Content-Length: {}\r\n\r\n{}", body.len(), body);
        let _ = self.writer.flush();
    }
}

// ---------------------------------------------------------------------------
// Adapter state
// ---------------------------------------------------------------------------

struct Dap {
    t: Transport,
    program: Option<PathBuf>,
    breakpoints: HashSet<u32>,
    vm: Option<Vm>,
    configured: bool,
    started: bool,
    stopped: bool,
}

/// Entry point for `yana-lsp --dap`.
pub fn serve_stdio() {
    let mut dap = Dap {
        t: Transport::new(),
        program: None,
        breakpoints: HashSet::new(),
        vm: None,
        configured: false,
        started: false,
        stopped: false,
    };

    loop {
        match dap.t.read_message() {
            Ok(Some(msg)) => {
                if msg["type"] == "request" {
                    let exit = dap.handle_request(&msg);
                    if exit {
                        break;
                    }
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
}

impl Dap {
    // ------------------------------------------------------------------
    // Message helpers
    // ------------------------------------------------------------------

    fn respond(&mut self, req: &Value, body: Option<Value>) {
        let mut resp = json!({
            "type": "response",
            "request_seq": req["seq"].as_i64().unwrap_or(0),
            "success": true,
            "command": req["command"].as_str().unwrap_or(""),
        });
        if let Some(b) = body {
            resp["body"] = b;
        }
        self.t.send(resp);
    }

    fn fail(&mut self, req: &Value, message: impl Into<String>) {
        let mut resp = json!({
            "type": "response",
            "request_seq": req["seq"].as_i64().unwrap_or(0),
            "success": false,
            "command": req["command"].as_str().unwrap_or(""),
            "message": message.into(),
        });
        resp["body"] = json!({ "error": resp["message"].clone() });
        self.t.send(resp);
    }

    fn event(&mut self, name: &str, body: Value) {
        self.t.send(json!({ "type": "event", "event": name, "body": body }));
    }

    // ------------------------------------------------------------------
    // Request dispatch
    // ------------------------------------------------------------------

    /// Returns `true` when the adapter should exit.
    fn handle_request(&mut self, req: &Value) -> bool {
        let command = req["command"].as_str().unwrap_or("").to_string();
        let args = req.get("arguments").cloned().unwrap_or_else(|| json!({}));

        match command.as_str() {
            "initialize" => {
                self.respond(req, Some(json!({ "capabilities": capabilities() })));
            }
            "launch" | "attach" => self.on_launch(req, &args),
            "configurationDone" => {
                self.configured = true;
                self.respond(req, None);
                if self.vm.is_some() {
                    self.start();
                }
            }
            "setBreakpoints" => self.on_set_breakpoints(req, &args),
            "setFunctionBreakpoints" => {
                self.respond(req, Some(json!({ "breakpoints": [] })));
            }
            "setExceptionBreakpoints" => {
                self.respond(req, Some(json!({ "breakpoints": [] })));
            }
            "setBreakpointLocations" => self.on_breakpoint_locations(req, &args),
            "threads" => {
                self.respond(
                    req,
                    Some(json!({ "threads": [{ "id": 1, "name": "main" }] })),
                );
            }
            "stackTrace" => self.on_stack_trace(req),
            "scopes" => {
                self.respond(
                    req,
                    Some(json!({
                        "scopes": [
                            { "name": "Registers", "variablesReference": 1, "expensive": false },
                            { "name": "Stack", "variablesReference": 2, "expensive": false },
                            { "name": "Flags", "variablesReference": 3, "expensive": false },
                        ]
                    })),
                );
            }
            "variables" => self.on_variables(req, &args),
            "evaluate" => self.on_evaluate(req, &args),
            "setVariable" => self.on_set_variable(req, &args),
            "continue" => self.on_continue(req),
            "next" => self.on_step(req, RunMode::StepOver),
            "stepIn" => self.on_step(req, RunMode::StepIn),
            "stepOut" => self.on_step(req, RunMode::StepOut),
            "pause" => {
                if self.vm.is_some() && self.stopped {
                    self.respond(req, None);
                    self.event(
                        "stopped",
                        json!({ "reason": "pause", "threadId": 1, "allThreadsStopped": true }),
                    );
                } else {
                    self.fail(req, "target is not stopped");
                }
            }
            "source" => self.on_source(req, &args),
            "modules" => self.on_modules(req),
            "loadedSources" => self.on_loaded_sources(req),
            "disconnect" | "terminate" => {
                self.respond(req, None);
                self.event("terminated", json!({}));
                return true;
            }
            "restart" => {
                self.fail(req, "restart is not supported; launch again");
            }
            other => {
                self.fail(req, format!("unsupported DAP request `{other}`"));
            }
        }

        false
    }

    // ------------------------------------------------------------------
    // Session lifecycle
    // ------------------------------------------------------------------

    fn on_launch(&mut self, req: &Value, args: &Value) {
        let Some(path) = program_path(args) else {
            self.fail(req, "launch: no `program` argument (expected a .yana file)");
            return;
        };

        let path = resolve_path(&path, args);

        let source = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                self.fail(req, format!("cannot read {}: {e}", path.display()));
                return;
            }
        };

        let parsed = yana_parser::parse(&source);
        if parsed.has_errors() {
            let msg = first_diagnostic(&parsed.diagnostics)
                .unwrap_or_else(|| "parse error".to_string());
            self.fail(req, format!("{}: {msg}", path.display()));
            return;
        }
        let Some(file) = parsed.file else {
            self.fail(req, "parse produced no AST");
            return;
        };

        let out = yana_codegen::resolve_module(
            &file,
            &yana_codegen::TargetInfo::linux_x86_64(),
            &yana_codegen::ResolveOptions::default(),
        );
        if out.has_errors() {
            let msg = first_diagnostic(&out.diagnostics)
                .unwrap_or_else(|| "resolve error".to_string());
            self.fail(req, format!("{}: {msg}", path.display()));
            return;
        }

        match Vm::new(out.module, source, path.clone()) {
            Ok(vm) => {
                self.vm = Some(vm);
                self.program = Some(path);
                self.started = false;
                self.stopped = true;

                self.respond(req, None);
                // DAP: tell the client it may now install breakpoints.
                self.event("initialized", json!({}));

                if self.configured {
                    self.start();
                }
            }
            Err(e) => self.fail(req, e),
        }
    }

    fn start(&mut self) {
        if self.started {
            return;
        }
        self.started = true;
        self.stopped = true;
        self.flush_output();
        // DAP clients (Helix 25.07 in particular) mark the adapter as "active"
        // only while handling `stopped`, so announce the thread first: that
        // registers thread 1 as the debuggee and makes the entry stop
        // continuable.
        self.event("thread", json!({ "reason": "started", "threadId": 1 }));
        self.event(
            "stopped",
            json!({ "reason": "entry", "threadId": 1, "allThreadsStopped": true }),
        );
    }

    fn report(&mut self, outcome: RunOutcome) {
        self.flush_output();
        match outcome {
            RunOutcome::Stopped(reason) => {
                self.stopped = true;
                self.event(
                    "stopped",
                    json!({ "reason": reason, "threadId": 1, "allThreadsStopped": true }),
                );
            }
            RunOutcome::Exited(code) => {
                self.stopped = false;
                self.event("terminated", json!({}));
                self.event("exited", json!({ "exitCode": code }));
            }
            RunOutcome::Fault(msg) => {
                self.stopped = true;
                self.event("output", json!({ "category": "stderr", "output": format!("{msg}\n") }));
                self.event(
                    "stopped",
                    json!({
                        "reason": "exception",
                        "threadId": 1,
                        "text": msg,
                        "allThreadsStopped": true
                    }),
                );
            }
        }
    }

    fn flush_output(&mut self) {
        let Some(vm) = self.vm.as_mut() else { return };
        if vm.output.is_empty() {
            return;
        }
        let bytes = std::mem::take(&mut vm.output);
        let text = String::from_utf8_lossy(&bytes).into_owned();
        self.event("output", json!({ "category": "stdout", "output": text }));
    }

    // ------------------------------------------------------------------
    // Breakpoints
    // ------------------------------------------------------------------

    fn on_set_breakpoints(&mut self, req: &Value, args: &Value) {
        let lines: Vec<u32> = args
            .get("breakpoints")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|b| b["line"].as_u64().map(|l| l as u32))
                    .collect()
            })
            .unwrap_or_default();

        self.breakpoints = lines.iter().copied().collect();

        let verified: Vec<Value> = lines
            .iter()
            .map(|line| {
                let ok = self.vm.as_ref().map(|vm| vm.has_line(*line)).unwrap_or(true);
                json!({
                    "verified": ok,
                    "line": line,
                    "source": args.get("source").cloned().unwrap_or_else(|| json!({})),
                    "message": if ok { Value::Null } else { json!("no code generated from this line") },
                })
            })
            .collect();

        self.respond(req, Some(json!({ "breakpoints": verified })));
    }

    fn on_breakpoint_locations(&mut self, req: &Value, args: &Value) {
        let line = args["line"].as_u64().unwrap_or(1) as u32;
        let end = args["endLine"].as_u64().map(|l| l as u32).unwrap_or(line);
        let mut out = Vec::new();
        if let Some(vm) = &self.vm {
            for l in line..=end.max(line) {
                if vm.has_line(l) {
                    out.push(json!({ "line": l, "column": 1 }));
                }
            }
        }
        self.respond(req, Some(json!({ "breakpoints": out })));
    }

    // ------------------------------------------------------------------
    // Inspection
    // ------------------------------------------------------------------

    fn on_stack_trace(&mut self, req: &Value) {
        let Some(vm) = &self.vm else {
            self.fail(req, "no debug session");
            return;
        };

        let mut frames = Vec::new();
        let (line, column) = vm.line_col_at(vm.body, vm.pc);
        frames.push(frame_json(
            1,
            &vm.fn_name_at(),
            &vm.path,
            line,
            column,
        ));

        let mut id = 2;
        for cs in vm.frames.iter().rev() {
            frames.push(frame_json(id, &cs.name, &vm.path, cs.line, cs.column));
            id += 1;
        }

        self.respond(
            req,
            Some(json!({ "stackFrames": frames, "totalFrames": frames.len() })),
        );
    }

    fn on_variables(&mut self, req: &Value, args: &Value) {
        let Some(vm) = &self.vm else {
            self.fail(req, "no debug session");
            return;
        };
        let reference = args["variablesReference"].as_u64().unwrap_or(0);

        let vars: Vec<Value> = match reference {
            1 => regs_of(vm)
                .iter()
                .map(|(name, value)| {
                    json!({
                        "name": name,
                        "value": format!("0x{value:016x}  ({value})"),
                        "type": "u64",
                        "evaluateName": name,
                        "variablesReference": 0,
                    })
                })
                .collect(),
            2 => {
                let rsp = vm.rsp();
                let mut out = Vec::new();
                for i in 0..32u64 {
                    let addr = rsp.wrapping_add(i * 8);
                    if addr > (crate::vm::MEM_SIZE as u64) {
                        break;
                    }
                    let v = vm.peek(addr);
                    out.push(json!({
                        "name": format!("[rsp+{}]", i * 8),
                        "value": format!("0x{v:016x}  ({v})"),
                        "type": "u64",
                        "evaluateName": format!("[rsp+{}]", i * 8),
                        "variablesReference": 0,
                    }));
                }
                out
            }
            3 => {
                let f = vm.flags;
                vec![
                    flag_json("cf", f.cf),
                    flag_json("zf", f.zf),
                    flag_json("sf", f.sf),
                    flag_json("of", f.of),
                    flag_json("pf", f.pf),
                ]
            }
            _ => Vec::new(),
        };

        self.respond(req, Some(json!({ "variables": vars })));
    }

    fn on_evaluate(&mut self, req: &Value, args: &Value) {
        let Some(vm) = &self.vm else {
            self.fail(req, "no debug session");
            return;
        };
        let expr = args["expression"].as_str().unwrap_or("").trim();

        if let Some(reg) = Reg::parse(expr) {
            let v = vm.get_reg(reg);
            self.respond(
                req,
                Some(json!({
                    "result": format!("{v} (0x{v:x})"),
                    "type": if reg.size() == RegSize::R64 { "u64" } else { "integer" },
                    "variablesReference": 0,
                })),
            );
            return;
        }

        if let Some(v) = parse_u64(expr) {
            self.respond(
                req,
                Some(json!({
                    "result": format!("{v} (0x{v:x})"),
                    "type": "u64",
                    "variablesReference": 0,
                })),
            );
            return;
        }

        // `[rsp+8]` / `[0x100000]` style memory reads.
        if let Some(inner) = expr.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some(addr) = eval_addr(vm, inner.trim()) {
                let v = vm.peek(addr);
                self.respond(
                    req,
                    Some(json!({
                        "result": format!("0x{v:016x} ({v})"),
                        "type": "u64",
                        "variablesReference": 0,
                    })),
                );
                return;
            }
        }

        self.fail(req, format!("cannot evaluate `{expr}` (try a register like `rax` or a number)"));
    }

    fn on_set_variable(&mut self, req: &Value, args: &Value) {
        let Some(vm) = self.vm.as_mut() else {
            self.fail(req, "no debug session");
            return;
        };
        let name = args["name"].as_str().unwrap_or("");
        let value = args["value"].as_str().unwrap_or("");
        let reference = args["variablesReference"].as_u64().unwrap_or(0);

        let parsed = parse_u64(value);

        match reference {
            1 => {
                let Some(reg) = Reg::parse(name) else {
                    self.fail(req, format!("unknown register `{name}`"));
                    return;
                };
                let Some(v) = parsed else {
                    self.fail(req, format!("cannot parse `{value}` as an integer"));
                    return;
                };
                vm.set_reg(reg, v);
                self.respond(req, Some(json!({ "value": format!("0x{v:x}"), "type": "u64" })));
            }
            3 => {
                let Some(flag) = parse_bool(value) else {
                    self.fail(req, "flags accept true/false/0/1");
                    return;
                };
                match name {
                    "cf" => vm.flags.cf = flag,
                    "zf" => vm.flags.zf = flag,
                    "sf" => vm.flags.sf = flag,
                    "of" => vm.flags.of = flag,
                    "pf" => vm.flags.pf = flag,
                    _ => {
                        self.fail(req, format!("unknown flag `{name}`"));
                        return;
                    }
                }
                self.respond(req, Some(json!({ "value": flag.to_string(), "type": "bool" })));
            }
            _ => self.fail(req, "this scope is read-only"),
        }
    }

    // ------------------------------------------------------------------
    // Execution control
    // ------------------------------------------------------------------

    fn on_continue(&mut self, req: &Value) {
        if self.vm.is_none() {
            self.fail(req, "no debug session");
            return;
        }
        if !self.stopped {
            self.fail(req, "target is already running");
            return;
        }
        self.respond(req, Some(json!({ "allThreadsContinued": true })));
        self.stopped = false;

        let outcome = {
            let vm = self.vm.as_mut().unwrap();
            vm.run(RunMode::Continue, &self.breakpoints)
        };
        self.report(outcome);
    }

    fn on_step(&mut self, req: &Value, mode: RunMode) {
        if self.vm.is_none() {
            self.fail(req, "no debug session");
            return;
        }
        if !self.stopped {
            self.fail(req, "target is running");
            return;
        }
        self.respond(req, None);
        self.stopped = false;

        let outcome = {
            let vm = self.vm.as_mut().unwrap();
            vm.run(mode, &self.breakpoints)
        };
        self.report(outcome);
    }

    // ------------------------------------------------------------------
    // Misc
    // ------------------------------------------------------------------

    fn on_source(&mut self, req: &Value, args: &Value) {
        let path = args["source"]["path"]
            .as_str()
            .map(PathBuf::from)
            .or_else(|| self.program.clone());

        match path.and_then(|p| std::fs::read_to_string(p).ok()) {
            Some(content) => self.respond(
                req,
                Some(json!({ "content": content, "mimeType": "text/x-yana" })),
            ),
            None => self.fail(req, "source not readable"),
        }
    }

    fn on_modules(&mut self, req: &Value) {
        let modules = match &self.program {
            Some(path) => vec![json!({
                "id": 1,
                "name": path.file_name().and_then(|n| n.to_str()).unwrap_or("yana"),
                "path": path.to_string_lossy(),
            })],
            None => Vec::new(),
        };
        self.respond(req, Some(json!({ "modules": modules, "totalModules": modules.len() })));
    }

    fn on_loaded_sources(&mut self, req: &Value) {
        let sources = match &self.program {
            Some(path) => vec![source_json(path)],
            None => Vec::new(),
        };
        self.respond(req, Some(json!({ "sources": sources })));
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn capabilities() -> Value {
    json!({
        "supportsConfigurationDoneRequest": true,
        "supportsEvaluateForHovers": true,
        "supportsSetVariable": true,
        "supportsTerminateRequest": true,
        "supportsSteppingGranularity": true,
        "supportsBreakpointLocationsRequest": true,
        "supportsLoadedSourcesRequest": true,
        "supportsModulesRequest": true,
        "supportsSingleThreadExecutionRequests": true,
        "supportsConditionalBreakpoints": false,
        "supportsHitConditionalBreakpoints": false,
        "supportsFunctionBreakpoints": false,
        "supportsInstructionBreakpoints": false,
        "supportsExceptionInfoRequest": false,
        "exceptionBreakpointFilters": [],
    })
}

fn program_path(args: &Value) -> Option<PathBuf> {
    for key in ["program", "file", "source", "path"] {
        if let Some(s) = args.get(key).and_then(|v| v.as_str()) {
            return Some(PathBuf::from(s));
        }
    }
    None
}

fn resolve_path(path: &Path, args: &Value) -> PathBuf {
    let mut p = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let base = args
            .get("cwd")
            .and_then(|v| v.as_str())
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_default();
        base.join(path)
    };
    if !p.exists() && p.extension().is_none() {
        p.set_extension("yana");
    }
    p
}

fn first_diagnostic(diags: &[yana_ast::Diagnostic]) -> Option<String> {
    diags
        .iter()
        .find(|d| matches!(d.level, yana_ast::DiagLevel::Error))
        .or_else(|| diags.first())
        .map(|d| format!("{}: {}", d.kind, d.message))
}

fn source_json(path: &Path) -> Value {
    json!({
        "name": path.file_name().and_then(|n| n.to_str()).unwrap_or("yana"),
        "path": path.to_string_lossy(),
    })
}

fn frame_json(id: i64, name: &str, path: &Path, line: u32, column: u32) -> Value {
    json!({
        "id": id,
        "name": name,
        "source": source_json(path),
        "line": line,
        "column": column,
    })
}

fn flag_json(name: &str, value: bool) -> Value {
    json!({
        "name": name,
        "value": value.to_string(),
        "type": "bool",
        "variablesReference": 0,
    })
}

/// All 16 GPRs in encoding order (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, …).
fn regs_of(vm: &Vm) -> Vec<(&'static str, u64)> {
    const BASES: [GprBase; 16] = [
        GprBase::A,
        GprBase::C,
        GprBase::D,
        GprBase::B,
        GprBase::Sp,
        GprBase::Bp,
        GprBase::Si,
        GprBase::Di,
        GprBase::R8,
        GprBase::R9,
        GprBase::R10,
        GprBase::R11,
        GprBase::R12,
        GprBase::R13,
        GprBase::R14,
        GprBase::R15,
    ];
    BASES
        .iter()
        .map(|&base| {
            let reg = Reg::Gpr { base, size: RegSize::R64 };
            (reg.name(), vm.get_reg(reg))
        })
        .collect()
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    let (negative, body) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let (radix, digits) = if let Some(rest) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        (16, rest)
    } else if let Some(rest) = body.strip_prefix("0b") {
        (2, rest)
    } else {
        (10, body)
    };
    let v = u64::from_str_radix(digits, radix).ok()?;
    Some(if negative { v.wrapping_neg() } else { v })
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

/// Evaluate `rsp+8`, `rsp`, `0x100000`, `rax*8` (register plus offset).
fn eval_addr(vm: &Vm, expr: &str) -> Option<u64> {
    let expr = expr.trim();
    if let Some(v) = parse_u64(expr) {
        return Some(v);
    }
    if let Some(reg) = Reg::parse(expr) {
        return Some(vm.get_reg(reg));
    }
    for (op, chr) in [('+', '+'), ('-', '-')] {
        let _ = op;
        if let Some(pos) = expr.rfind(chr) {
            let (lhs, rhs) = expr.split_at(pos);
            let rhs = &rhs[1..];
            let base = if let Some(r) = Reg::parse(lhs.trim()) {
                vm.get_reg(r)
            } else {
                parse_u64(lhs.trim())?
            };
            let off = parse_u64(rhs.trim())?;
            return Some(if chr == '+' {
                base.wrapping_add(off)
            } else {
                base.wrapping_sub(off)
            });
        }
    }
    None
}
