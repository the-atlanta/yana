; YANA highlights — register names are idents lexically; mark the common
; GPR set explicitly (matches the closed register table in yana-ast).

[
  "bind" "alt" "push" "pop" "branch" "call" "return" "syscall" "label"
  "fn" "extern" "const" "clobbers" "as"
  "if" "else"
] @keyword

(mut) @keyword
(pub) @keyword

[
  "u8" "u16" "u32" "u64" "u128" "usize"
  "i8" "i16" "i32" "i64" "i128" "isize"
] @type.builtin
(prim_type) @type.builtin
(bool) @boolean

; Registers are lexically idents in the editor grammar; match the closed
; GPR/XMM set with a regex predicate (#match? is supported by Zed).
(
  (ident) @variable.builtin
  (#match? @variable.builtin
    "^(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|eax|ebx|ecx|edx|esi|edi|ebp|esp|ax|bx|cx|dx|si|di|bp|sp|al|bl|cl|dl|ah|bh|ch|dh|spl|bpl|sil|dil|r8|r9|r10|r11|r12|r13|r14|r15|r8d|r8w|r8b|r8l|r9d|r9w|r9b|r9l|r10d|r10w|r10b|r10l|r11d|r11w|r11b|r11l|r12d|r12w|r12b|r12l|r13d|r13w|r13b|r13l|r14d|r14w|r14b|r14l|r15d|r15w|r15b|r15l|rip|xmm0|xmm1|xmm2|xmm3|xmm4|xmm5|xmm6|xmm7|xmm8|xmm9|xmm10|xmm11|xmm12|xmm13|xmm14|xmm15)$")
)

[
  "zero" "carry" "negative" "overflow" "even"
] @constant.builtin
(flag) @constant.builtin

(section) @namespace

(attribute name: (ident) @attribute)

(comment) @comment

(string) @string
(char) @string.special.character
(int) @number
(label_ref) @label

(fn_item name: (ident) @function)
(extern_fn name: (ident) @function)
(const_fn name: (ident) @function)
(call_stmt name: (ident) @function.call)
(label_stmt name: (ident) @label)

(bind_stmt name: (ident) @variable)
(static_bind name: (ident) @variable)
(const_item name: (ident) @constant)
(param name: (ident) @variable.parameter)
(destructure (ident) @variable)

[
  "=" "+=" "-=" "*=" "^=" "&=" "|=" "<<=" ">>="
  "==" "!=" "<" "<=" ">" ">="
  "+" "-" "*" "/" "%" "&" "|" "^" "<<" ">>" "&&" "||"
  "/%"
] @operator

[
  "(" ")" "{" "}" "[" "]"
] @punctuation.bracket

["," ";" ":" "@" "=>" "->" "." "'" "!"] @punctuation.delimiter
