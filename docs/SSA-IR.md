# YANA SSA-IR — пример для `test.yn`

Статус: **черновик синтаксиса**. Ничего ещё не реализовано; это эталон того,
как должен выглядеть дамп `yana ir test.yn --ssa`, чтобы по нему можно было
делать оптимизации, верификацию и отладку.

Модель: **physical-register SSA**. Каждая запись в архитектурный регистр
создаёт новую версию (`%rax.0`, `%rax.1`, …). Память, флаги и `%rsp` — такие
же явные state-значения, поэтому def-use покрывает всё состояние машины, а не
только «виртуальные» переменные. Исходные имена (`fd`, `n`, `n1`) — это
метаданные `!bind`, а не отдельные сущности. `unbind` не генерирует машинный
код: он становится псевдоинструкцией `virt unbind <name>`, которая снимает
имя, но оставляет SSA-значение живым до последнего использования.

Пометки в комментариях:

| тег | кто пишет | что означает |
|---|---|---|
| `[resolve]` | резолвер | как исходник превратился в IR, почему это легально |
| `[ssa]` | построение SSA | откуда взялась версия значения, где ломается def-use |
| `[abi]` | ABI-lowering | почему аргумент оказался именно в этом регистре |
| `[opt]` | оптимизатор | что можно/нельзя сделать и почему |
| `[codegen]` | бэкенд | в какую машинную инструкцию это превратится |
| `[cost]` | cost model | байты / µops / такты |
| `[verify]` | верификатор | какие инварианты проверены |
| `[contract]` | контракты | clobbers/preserves/effects вызываемого |
| `[diag]` | диагностика | предупреждение, привязанное к IR-узлу |

---

```llvm
; ============================================================================
;  YANA SSA-IR  ·  module dump
;  --------------------------------------------------------------------------
;  source        test.yn
;  command       yana ir test.yn --ssa --comments --stats
;  compiler      yana 0.1.0 (debug) · commit 731140f · 2026-11-03
;  pipeline      lex → parse → resolve → ssa-construct → verify → dump
;  target        x86_64-unknown-linux-gnu
;  abi           SysV AMD64 + Linux syscall ABI (no libc)
;  --------------------------------------------------------------------------
;  stats         symbols 4 · functions 2 · externs 2 · globals 0
;                blocks 3 · instructions 27 · ssa values 31 · phi 0
;                stack max 24 B · spills 0 · diagnostics 1 warning
;  --------------------------------------------------------------------------
;  model         physical-register SSA. Every write to an architectural
;                register creates a new version (%rax.0, %rax.1, …).
;                Memory, flags and rsp are explicit state values, so the
;                def-use graph covers the whole machine state.
; ============================================================================

source_filename = "test.yn"
target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target cpu = "generic"
target features = "+cx16,+sse2"

; [compiler] named metadata: версия, пайплайн, все диагностики и opt-заметки.
!yana.module      = !{!0}
!yana.passes      = !{!1}
!yana.diagnostics = !{!70, !71}

!0 = !{!"YANA", !"0.1.0", !"731140f", !"debug", !"2026-11-03"}
!1 = !{!"lex", !"parse", !"resolve", !"ssa-construct", !"verify", !"dump"}


; ---------------------------------------------------------------------------
; type definitions
; ---------------------------------------------------------------------------
; [resolve] `b"..."` имеет тип [N x i8]; при записи в регистр байты
;           упаковываются little-endian в ближайшее целое, которое влезает.
%bytes5 = type [5 x i8]


; ===========================================================================
; extern declarations
; ===========================================================================

; ┌─────────────────────────────────────────────────────────────────────────┐
; │ extern fn sys_write(fd @ rdi: u64, buf @ rsi: *u8, len @ rdx: u64)     │
; │            -> rax: i64                      #[syscall(1)]               │
; └─────────────────────────────────────────────────────────────────────────┘
;
; [resolve] номер syscall'а — факт контракта (`syscall 1`), а не аргумент.
;           Символ не линкуется ни с каким libc, вызов идёт через `syscall`.
; [abi]     fd→rdi · buf→rsi · len→rdx · ret→rax. Ни пролога, ни PLT.
; [effects] пишет ровно len байт через buf; читает только argmem; convergent.
; [clobber] сама инструкция `syscall` разрушает rcx (saved RIP) и r11
;           (saved RFLAGS). Оба регистра перечислены, чтобы liveness был
;           точным и не приходилось консервативно считать «всё живым».
; [cost]    syscall ≈ 100–300 тактов (зависит от ядра); в -O0 не моделируется.
declare i64 @sys_write(i64 %fd, ptr %buf, i64 %len)
    syscall 1
    abi = { fd: rdi, buf: rsi, len: rdx, ret: rax }
    effects = { memory: write(argmem: %buf, len: %len), convergent, nounwind }
    clobbers = [rcx, r11]
    !contract !10
    !span !11

; ┌─────────────────────────────────────────────────────────────────────────┐
; │ extern fn sys_exit(code @ rdi: u64) -> !        #[syscall(60)]          │
; └─────────────────────────────────────────────────────────────────────────┘
;
; [resolve] `-> !` — noreturn-контракт. Верификатор запрещает блок, который
;           «проваливается» за этот вызов.
; [effects] памяти не трогает, не возвращается, наблюдаемый side effect
;           (завершение процесса).
; [opt]     после noreturn-вызова весь последующий код в блоке недостижим;
;           SSA-построение даже не создаёт для него значений.
declare noreturn void @sys_exit(i64 %code)
    syscall 60
    abi = { code: rdi }
    effects = { noreturn, nounwind, sideeffect }
    clobbers = [rcx, r11]
    !contract !12
    !span !13


; ===========================================================================
; fn say_hi_to_fd(fd @ rdi: u64) -> rax: i64
;     clobbers: rax
; ===========================================================================
;
; [resolve] `-> rax` объявляет return-place на всё тело функции, поэтому
;           `alt rax = ...` легален, хотя `bind` с именем rax нигде нет
;           (result_regs содержит rax; §4.2).
; [abi]     один целочисленный аргумент в rdi, результат в rax. Спиллить
;           нечего: callee-saved регистры не трогаются.
; [stack]   максимальная динамическая глубина 8 B (один push); frame pointer
;           не нужен, красная зона тоже не используется.
define i64 @say_hi_to_fd(i64 %fd)
    abi = { arg0: rdi, ret: rax }
    clobbers = [rax]
    preserves = [rbx, rbp, r12, r13, r14, r15]
    stack = { frame: 0, incoming_args: 0, max_depth: 8, alignment: 16 }
    !fn !20
    !span !21
{
entry:
    ; [abi] entry state. `%fd` — source-level alias для %rdi.0.
    ;       `unbind fd` здесь был бы ошибкой `unbind-param`: параметр
    ;       живёт всё тело функции.
    %rdi.0 = arg i64 0, reg rdi, !bind !22
    %rsp.0 = stack.entry, !stack !23

    ; [resolve] `alt rax = b"Haii\n";`  (test.yn:15)
    ; [ssa]     запись в rax создаёт %rax.0; предыдущего значения rax нет,
    ;           поэтому это определение, а не переопределение.
    ; [opt]     константа свёрнута ещё резолвером: b"Haii\n" упаковано
    ;           little-endian в 0x0a69696148 (байты 48 61 69 69 0a).
    ; [codegen] → mov rax, 0x0a69696148          ; 10 B, imm64
    ; [cost]    1 µop, 10 B. `mov eax, imm32` не подходит (значение > 32 бит),
    ;           `push imm32` тоже не достаёт до 5 байт.
    %rax.0 = mov i64 0x0a69696148, !bind !24, !span !25

    ; [resolve] `push { rax };`  (test.yn:16)
    ; [effects] пишет 8 B по rsp-8 и уменьшает rsp на 8.
    ; [ssa]     push — state-инструкция: возвращает новый rsp и токен слота.
    ;           Записанное значение остаётся адресуемым через %slot0.
    ; [opt]     слот «убегает»: его адрес передаётся в sys_write, поэтому
    ;           store-to-load forwarding и SROA заблокированы (escaped).
    ; [codegen] → push rax                        ; 1 B
    %rsp.1, %slot0 = push i64 %rax.0, %rsp.0, !span !26

    ; [resolve] `call sys_write { fd: rdi @ rdi, len: 5, buf: rsp @ rsp };`
    ;           (test.yn:17–21)
    ; [abi]     fd уже в rdi — assertion `@ rdi` совпал, копия не нужна.
    ;           buf: rsp нужно переложить в rsi; len: 5 → rdx.
    ; [opt]     `mov rsi, rsp` не удаляется: регистратор не может сделать
    ;           алиас двух разных физических регистров. Это 3 B.
    ; [opt]     `mov rdx, 5` можно заменить на `mov edx, 5` (5 B, zero-extend),
    ;           но кодогенератор пока выбирает `mov rdx, 5` (7 B).
    ; [clobber] rcx/r11 умирают на syscall'е и после него не живые —
    ;           spill/reload не вставляется.
    %rsi.0 = mov ptr %rsp.1, !abi.copy !27
    %rdx.0 = mov i64 5, !abi.const !28
    %rax.1 = mov i64 1, !abi.syscall_nr !29
    %rax.2, %rcx.0, %r11.0 = syscall @sys_write(%rdi.0, %rsi.0, %rdx.0)
        !call !30
        !effects !31
        !cost !32

    ; [resolve] `pop { _ };`  (test.yn:22) — `_` это discard sink, а не
    ;           привязка: имя не определяется, вытащенное значение
    ;           выбрасывается.
    ; [effects] rsp += 8; 8 байт выше rsp становятся undefined.
    ; [ssa]     версионируется только стек-поинтер, данных-результата нет.
    ; [codegen] → lea rsp, [rsp+8]                ; 5 B
    ;           (`pop rcx` был бы 1 B, но клобберит rcx, который контракт
    ;            не разрешает трогать в эпилоге)
    %rsp.2 = pop void, %rsp.1, !span !33

    ; [resolve] `return;`  (test.yn:23)
    ; [verify]  definedness: %rax.2 определён на всех путях до этого ret.
    ; [abi]     результат уже лежит в rax — ровно там, где его оставил
    ;           sys_write; эпилоговой копии не нужно.
    ret i64 %rax.2, !span !34
}


; ===========================================================================
; #[entry] fn main() -> !
; ===========================================================================
;
; [resolve] `#[entry]` переименовывает символ в `_start` под Linux и делает
;           его global. Исходное имя `main` остаётся в !fn.
; [abi]     вход из ядра, а не из call: rsp выровнен на 16 и указывает на
;           argc. Возвратного адреса и возвращаемого значения нет.
; [verify]  `-> !` + noreturn sys_exit ⇒ достижимого `ret` нет; блок
;           обязан закончиться `unreachable`.
define noreturn void @main()
    symbol = "_start"
    abi = { entry: true, ret: none, stack_alignment: 16 }
    !fn !40
    !span !41
{
entry:
    %rsp.0 = stack.entry, !stack !42

    ; [resolve] `bind _ @ rax:u64 = 1;`  (test.yn:28)
    ; [ssa]     `_` — discard sink: запись происходит, но исходное имя не
    ;           вводится. reg_names[rax] = "_" только для liveness, поэтому
    ;           следующий `bind n @ rax` не считается reg-conflict.
    ; [codegen] → mov rax, 1                      ; 7 B (mov r64, imm32)
    %rax.0 = mov i64 1, !bind !43, !span !44

    ; [resolve] `push { rax };`  (test.yn:30)
    ; [opt]     мёртвый стек-трафик: %slot0 никогда не читается. DSE может
    ;           удалить push на -O1; на -O0 он сохранён, чтобы дамп
    ;           соответствовал исходнику один-в-один.
    %rsp.1, %slot0 = push i64 %rax.0, %rsp.0, !span !45

    ; [resolve] `bind n @ rax:u64 = 1;`  (test.yn:32)
    ; [ssa]     новое определение rax; `n` привязан к %rax.1.
    ; [opt]     const-cse: %rax.0 и %rax.1 материализуют одну и ту же 1.
    ;           CSE может схлопнуть определения; push'и всё равно читают
    ;           разные слоты.
    ; [bindings] n → %rax.1
    %rax.1 = mov i64 1, !bind !46, !span !47

    %rsp.2, %slot1 = push i64 %rax.1, %rsp.1, !span !48

    ; [resolve] `unbind n;`  (test.yn:36)
    ; [ssa]     `virt unbind` — псевдоинструкция: ноль машинных байт,
    ;           только правка таблицы имён. %rax.1 остаётся валидным
    ;           SSA-значением до последнего использования; имя `n`
    ;           просто перестаёт резолвиться.
    ;           Именно unbind делает следующий `bind n1 @ rax` легальным
    ;           (без reg-conflict).
    ; [bindings] n → (retired)
    virt unbind n, !bind !49, !span !50

    ; [resolve] `bind n1 @ rax:u64 = 1;`  (test.yn:37)
    ; [bindings] n1 → %rax.2
    %rax.2 = mov i64 1, !bind !51, !span !52

    %rsp.3, %slot2 = push i64 %rax.2, %rsp.2, !span !53

    ; [resolve] `call say_hi_to_fd { fd: rax };`  (test.yn:41–43)
    ; [abi]     fd едет в rdi; источник — rax, поэтому нужна копия.
    ; [opt]     копия 3 B. Так как %rax.2 — константа 1, на -O1 возможен
    ;           peephole `mov rdi, 1` (убирает зависимость от rax).
    ; [contract] заявленные clobbers кале: [rax]. Верификатор доверяет
    ;           контракту и выдаст `clobber-mismatch`, если кале пишет
    ;           что-то ещё и не восстанавливает.
    ; [opt]     мёртвый результат: %rax.3 нигде не используется. Сам вызов
    ;           удалить нельзя (callee не readnone — пишет в stdout), но
    ;           результат можно игнорировать.
    ; [align]   после трёх push'ей rsp ≡ 8 (mod 16); call добавляет
    ;           return address, и callee входит с rsp ≡ 0 (mod 16), а SysV
    ;           ожидает 8. Здесь безобидно (в кале нет aligned SSE), но -O1
    ;           либо выкинет мёртвые push'и, либо вставит `sub rsp, 8`.
    %rdi.0 = mov i64 %rax.2, !abi.copy !54
    %rax.3 = call i64 @say_hi_to_fd(%rdi.0)
        !call !55
        !effects !56
        !cost !57

    ; [resolve] `call sys_exit { code: 0 };`  (test.yn:47)
    ; [abi]     code → rdi, номер syscall'а 60 → rax.
    ; [opt]     `xor edi, edi` (2 B) короче `mov rdi, 0` (7 B) и тоже
    ;           обнуляет rdi. На -O0 кодогенератор оставляет `mov rdi, 0`.
    ; [verify]  noreturn: ребра к `ret` нет; `unreachable` обязателен и
    ;           является единственным продолжением.
    %rdi.1 = mov i64 0, !abi.const !58
    %rax.4 = mov i64 0x3c, !abi.syscall_nr !59
    call noreturn void @sys_exit(%rdi.1)
        !call !60
        !effects !61
        !cost !62
    unreachable
}


; ===========================================================================
; metadata
; ===========================================================================

; ---- module ---------------------------------------------------------------
; !0, !1 — см. шапку.

; ---- contracts ------------------------------------------------------------
; [contract] sys_write: syscall 1, fd/rdi · buf/rsi · len/rdx → rax,
;            пишет argmem, convergent.
!10 = !{!"contract", !"sys_write", !"syscall", i64 1,
        !"fd",  !"rdi", !"u64",
        !"buf", !"rsi", !"ptr",
        !"len", !"rdx", !"u64",
        !"ret", !"rax", !"i64",
        !"memory", !"write", !"argmem", !"convergent"}
!11 = !{!"test.yn", i32 1, i32 1, i32 6, i32 2}

; [contract] sys_exit: syscall 60, code/rdi, noreturn, sideeffect.
!12 = !{!"contract", !"sys_exit", !"syscall", i64 60,
        !"code", !"rdi", !"u64",
        !"ret",  !"none", !"!",
        !"noreturn", !"sideeffect"}
!13 = !{!"test.yn", i32 8, i32 1, i32 9, i32 34}

; ---- say_hi_to_fd ---------------------------------------------------------
!20 = !{!"fn", !"say_hi_to_fd", !"sym#2", !"local",
        !"abi", !"sysv64", !"clobbers", !"rax",
        !"stack", i32 8, !"align", i32 16}
!21 = !{!"test.yn", i32 11, i32 1, i32 24, i32 2}
!22 = !{!"bind", !"fd", !"param", !"rdi", !"u64", i1 true,
        !"alias", !"%rdi.0"}
!23 = !{!"stack", !"entry", !"rsp", i32 0, i32 16}
!24 = !{!"bind", !"rax", !"return-place", !"rax", !"i64", i1 true}
!25 = !{!"test.yn", i32 15, i32 5, i32 15, i32 28}
!26 = !{!"test.yn", i32 16, i32 5, i32 16, i32 18}
!27 = !{!"abi.copy", !"arg", !"buf", !"rsp", !"rsi", !"ptr",
        !"reason", !"abi"}
!28 = !{!"abi.const", !"arg", !"len", i64 5, !"fits", !"imm32"}
!29 = !{!"abi.syscall_nr", !"sys_write", i64 1, !"reg", !"rax"}
!30 = !{!"call", !"sys_write", !"direct", !"syscall",
        !"site", !"test.yn:17:5"}
!31 = !{!"effects", !"memory.write", !"argmem", i64 5,
        !"convergent", !"nounwind"}
!32 = !{!"cost", i32 2, i32 1, i32 10, !"syscall nr + push"}
!33 = !{!"test.yn", i32 22, i32 5, i32 22, i32 14}
!34 = !{!"test.yn", i32 23, i32 5, i32 23, i32 12}

; ---- main -----------------------------------------------------------------
!40 = !{!"fn", !"main", !"sym#3", !"global", !"symbol", !"_start",
        !"entry", i1 true, !"noreturn", i1 true}
!41 = !{!"test.yn", i32 26, i32 1, i32 48, i32 2}
!42 = !{!"stack", !"entry", !"rsp", i32 0, i32 16, !"kernel", i1 true}
; [bind] unbind n: имя снято; значение %rax.1 живо до последнего use.
!49 = !{!"bind", !"n", !"unbind", !"rax", !"u64"}
!50 = !{!"test.yn", i32 36, i32 5, i32 36, i32 14}
!43 = !{!"bind", !"_", !"discard", !"rax", !"u64", i1 false}
!44 = !{!"test.yn", i32 28, i32 5, i32 28, i32 25}
!45 = !{!"test.yn", i32 30, i32 5, i32 30, i32 18}
!46 = !{!"bind", !"n", !"local", !"rax", !"u64", i1 false}
!47 = !{!"test.yn", i32 32, i32 5, i32 32, i32 25}
!48 = !{!"test.yn", i32 34, i32 5, i32 34, i32 18}
!51 = !{!"bind", !"n1", !"local", !"rax", !"u64", i1 false}
!52 = !{!"test.yn", i32 37, i32 5, i32 37, i32 26}
!53 = !{!"test.yn", i32 39, i32 5, i32 39, i32 18}
!54 = !{!"abi.copy", !"arg", !"fd", !"rax", !"rdi", !"u64",
        !"reason", !"abi"}
!55 = !{!"call", !"say_hi_to_fd", !"direct", !"site", !"test.yn:41:5",
        !"clobbers", !"rax", !"contract", !"trusted"}
!56 = !{!"effects", !"memory.write", !"external", !"sideeffect",
        !"nounwind"}
!57 = !{!"cost", i32 5, i32 1, i32 3, !"call rel32"}
!58 = !{!"abi.const", !"arg", !"code", i64 0, !"fits", !"imm32",
        !"alt", !"xor edi,edi"}
!59 = !{!"abi.syscall_nr", !"sys_exit", i64 60, !"reg", !"rax"}
!60 = !{!"call", !"sys_exit", !"direct", !"syscall", !"noreturn", i1 true}
!61 = !{!"effects", !"noreturn", !"sideeffect", !"nounwind"}
!62 = !{!"cost", i32 7, i32 1, i32 1, !"mov imm32"}

; ---- diagnostics / optimizer notes ---------------------------------------
; [diag] выравнивание стека на call-site (безобидно для этого кале).
!70 = !{!"warning", !"stack-align", !"test.yn:41:5",
        !"call site rsp ≡ 8 (mod 16); callee entry ≡ 0, SysV expects 8",
        !"benign: callee has no aligned SSE access"}
; [opt] мёртвый push в main; кандидат на DSE, на -O0 оставлен.
!71 = !{!"note", !"opt", !"dead-push", !"test.yn:30:5",
        !"slot is never read; removable at -O1"}
```

---

## Что именно даёт такая форма

1. **Def-use без догадок.** `%rax.2` — это одно определение и все его
   использования. Не нужно заново сканировать `mov`/`push`/`pop`, чтобы
   понять, что живое.
2. **`bind` — это не инструкция, а `unbind` — псевдоинструкция.**
   `bind n @ rax = 1` даёт `%rax.1 = mov 1` и `!bind {name: "n", value: %rax.1}`.
   `unbind n` превращается в `virt unbind n`: ноль машинных байт, только
   запись в таблице имён. Поэтому `n1 @ rax` после `unbind` не конфликтует:
   это новое SSA-определение того же регистра, а `%rax.1` остаётся живым
   до последнего использования.
3. **Память и стек явные.** `push` возвращает `(%rsp.1, %slot0)`, `pop` —
   новый `%rsp.2`. DSE видит, что `%slot0` в `main` никто не читает, и может
   убрать push.
4. **Точные clobbers.** `syscall` перечисляет `rcx`/`r11`; `call` — только
   то, что заявлено в контракте кале. Liveness не консервативен.
5. **Контракты и effects.** `sys_write` помечен как пишущий `argmem`, поэтому
   его нельзя выкинуть как `readnone`, но можно переставлять относительно
   чистых вычислений.
6. **Span на каждом значении.** Любая оптимизация, удалившая инструкцию,
   может объяснить, какую строку `test.yn` она удалила (и DAP/LSP могут
   показать это в обратную сторону).
7. **Cost model в IR.** `!cost` позволяет сравнивать варианты
   (`mov rdi,0` vs `xor edi,edi`) не в бэкенде, а на уровне оптимизатора.
8. **Верификатор на уровне IR.** `[verify]`-пометки — это не комментарии
   ради комментариев: `definedness`, `noreturn`, `stack-align`,
   `clobber-mismatch` проверяются до кодогенерации.

## Как это лоуерится в текущий machine IR

| SSA-IR | `yana_codegen::Insn` |
|---|---|
| `%rax.0 = mov i64 0x0a69696148` | `Mov { dst: rax, src: Imm(0x0a69696148), size: 64 }` |
| `%rsp.1, %slot0 = push i64 %rax.0, %rsp.0` | `Push { item: Reg(rax) }` |
| `%rax.2, %rcx.0, %r11.0 = syscall @sys_write(...)` | `Syscall` (+ таблица effects) |
| `%rsp.2 = pop void, %rsp.1` | `StackSlot { grow: false }` / `Lea rsp,[rsp+8]` |
| `ret i64 %rax.2` | `Ret` |
| `!bind` | `FnBody::reg_names` + `Binding` |
| `!span` | `Insn::span` (уже есть) |

То есть SSA-IR — это **надстройка над текущим machine IR**, а не замена
бэкендов: резолвер начнёт эмитить SSA-значения, затем отдельный pass
«сплющит» версии в физические регистры и отдаст те же `Insn`, что и сейчас.
Бэкенды (iced, NASM, Mach-O, будущие AArch64/Xtensa) не меняются.

## Приложение: как выглядит phi (не из `test.yn`)

Чтобы было видно, что модель не ломается на циклах:

```llvm
; [ssa] на слиянии двух путей создаётся phi; версии регистров не нужны,
;       потому что это уже честные SSA-значения.
define i64 @sum(i64 %n) {
entry:
  br label %loop

loop:
  %i   = phi i64 [ 0, %entry ], [ %i.next, %loop ]
  %acc = phi i64 [ 0, %entry ], [ %acc.next, %loop ]

  %acc.next = add i64 %acc, %i
  %i.next   = add i64 %i, 1
  %done     = icmp eq i64 %i.next, %n

  ; [opt] loop-rotate + indvar: сравнение можно перенести в конец,
  ;       чтобы убрать одну проверку на входе.
  br i1 %done, label %exit, label %loop

exit:
  ret i64 %acc.next
}
```
