use codespan::Span;
use fnv::FnvHashMap;

#[derive(Clone, Debug)]
pub struct Program {
    pub fns: FnvHashMap<String, Fn>,
}

#[derive(Clone, Debug)]
pub struct Fn {
    pub span: Span,
    pub fn_token: SimpleToken,
    pub name: Ident,
    pub start_paren: SimpleToken,
    pub args: Option<FnArgs>,
    pub end_paren: SimpleToken,
    pub block: Block,
}

#[derive(Clone, Debug)]
pub struct FnArgs {
    pub first: Ident,
    pub more: Vec<(SimpleToken, Ident)>,
    pub final_comma: Option<SimpleToken>,
}

#[derive(Clone, Debug)]
pub struct Block {
    pub span: Span,
    pub start_brace: SimpleToken,
    pub statements: Vec<Statement>,
    pub end_brace: SimpleToken,
}

#[derive(Clone, Debug)]
pub struct Statement {
    pub span: Span,
    pub kind: StatementKind,
    pub semicolon: Option<SimpleToken>,
}

#[derive(Clone, Debug)]
pub enum StatementKind {
    Box {
        keyword: SimpleToken,
    },
    Wire {
        keyword: SimpleToken,
    },
    Head {
        keyword: SimpleToken,
    },
    Tail {
        keyword: SimpleToken,
    },
    Delete {
        keyword: SimpleToken,
    },
    Forward {
        keyword: SimpleToken,
        value: Option<Expr>,
    },
    Back {
        keyword: SimpleToken,
        value: Option<Expr>,
    },
    Left {
        keyword: SimpleToken,
        value: Option<Expr>,
    },
    Right {
        keyword: SimpleToken,
        value: Option<Expr>,
    },
    Up {
        keyword: SimpleToken,
        value: Option<Expr>,
    },
    Down {
        keyword: SimpleToken,
        value: Option<Expr>,
    },
    LookLeft {
        keyword: SimpleToken,
        direction: SimpleToken,
    },
    LookRight {
        keyword: SimpleToken,
        direction: SimpleToken,
    },
    LookBack {
        keyword: SimpleToken,
        direction: SimpleToken,
    },
    LookUp {
        keyword: SimpleToken,
        direction: SimpleToken,
    },
    LookDown {
        keyword: SimpleToken,
        direction: SimpleToken,
    },
    RollLeft {
        keyword: SimpleToken,
        direction: SimpleToken,
    },
    RollRight {
        keyword: SimpleToken,
        direction: SimpleToken,
    },
    Assign {
        left: AssignTarget,
        eq: SimpleToken,
        right: Expr,
    },
    Expr(Expr),
    Return {
        keyword: SimpleToken,
        expr: Expr,
    },
    For {
        for_: SimpleToken,
        var: Ident,
        in_: SimpleToken,
        start: Expr,
        dotdot: SimpleToken,
        end: Expr,
        block: Block,
    },
    If {
        if_: SimpleToken,
        expr: Expr,
        block: Block,
        elifs: Vec<ElifGroup>,
        else_: Option<ElseGroup>,
    },
    Block(Block),
}

#[derive(Clone, Debug)]
pub struct ElifGroup {
    pub else_: SimpleToken,
    pub if_: SimpleToken,
    pub expr: Expr,
    pub block: Block,
}

#[derive(Clone, Debug)]
pub struct ElseGroup {
    pub else_: SimpleToken,
    pub block: Block,
}

#[derive(Clone, Debug)]
pub enum AssignTarget {
    Variable(Ident),
    Tuple {
        init: Ident,
        rest: Vec<(SimpleToken, Ident)>,
        final_comma: Option<SimpleToken>,
    },
}

#[derive(Clone, Debug)]
pub struct Expr {
    pub span: Span,
    pub kind: ExprKind,
}

#[derive(Clone, Debug)]
pub enum ExprKind {
    Variable(Ident),
    Int(Int),
    Bool(bool),
    Tuple {
        start: SimpleToken,
        init: Box<Expr>,
        rest: Vec<(SimpleToken, Expr)>,
        final_comma: Option<SimpleToken>,
        end: SimpleToken,
    },
    Paren {
        start: SimpleToken,
        inner: Box<Expr>,
        end: SimpleToken,
    },
    Plus {
        left: Box<Expr>,
        op: SimpleToken,
        right: Box<Expr>,
    },
    Minus {
        left: Box<Expr>,
        op: SimpleToken,
        right: Box<Expr>,
    },
    Mul {
        left: Box<Expr>,
        op: SimpleToken,
        right: Box<Expr>,
    },
    Div {
        left: Box<Expr>,
        op: SimpleToken,
        right: Box<Expr>,
    },
    Mod {
        left: Box<Expr>,
        op: SimpleToken,
        right: Box<Expr>,
    },
    And {
        left: Box<Expr>,
        op: SimpleToken,
        right: Box<Expr>,
    },
    Or {
        left: Box<Expr>,
        op: SimpleToken,
        right: Box<Expr>,
    },
    Xor {
        left: Box<Expr>,
        op: SimpleToken,
        right: Box<Expr>,
    },
    Call {
        name: Ident,
        start_paren: SimpleToken,
        args: Option<CallArgs>,
        end_paren: SimpleToken,
    },
    Equals {
        left: Box<Expr>,
        eq: SimpleToken,
        right: Box<Expr>,
    },
    NotEquals {
        left: Box<Expr>,
        neq: SimpleToken,
        right: Box<Expr>,
    },
    Less {
        left: Box<Expr>,
        less: SimpleToken,
        right: Box<Expr>,
    },
    LessEq {
        left: Box<Expr>,
        less_eq: SimpleToken,
        right: Box<Expr>,
    },
    Greater {
        left: Box<Expr>,
        greater: SimpleToken,
        right: Box<Expr>,
    },
    GreaterEq {
        left: Box<Expr>,
        greater_eq: SimpleToken,
        right: Box<Expr>,
    },
    BAnd {
        left: Box<Expr>,
        op: SimpleToken,
        right: Box<Expr>,
    },
    BOr {
        left: Box<Expr>,
        op: SimpleToken,
        right: Box<Expr>,
    },
    Not {
        op: SimpleToken,
        expr: Box<Expr>,
    },
}

#[derive(Clone, Debug)]
pub struct CallArgs {
    pub first: Box<Expr>,
    pub more: Vec<(SimpleToken, Expr)>,
    pub final_comma: Option<SimpleToken>,
}

#[derive(Clone, Debug)]
pub struct Ident {
    pub span: Span,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct Int {
    pub span: Span,
    pub sign: Option<SimpleToken>,
    pub value: SimpleToken,
    pub value_interpreted: i128,
}

#[derive(Clone, Debug)]
pub struct SimpleToken {
    pub span: Span,
}
