use codespan::{ByteIndex, Span};
use logos::Logos;

use crate::error::LexicalError;

#[derive(Logos, Clone, PartialEq, Eq, Debug)]
#[logos(skip r"[ \t\n\f]+")]
#[logos(skip r"//[^\n]*")]
pub enum Token<'input> {
    #[token("{")]
    BraceOpen,

    #[token("}")]
    BraceClose,

    #[token("(")]
    ParOpen,

    #[token(")")]
    ParClose,

    #[token("[")]
    BracketOpen,

    #[token("]")]
    BracketClose,

    #[token(".")]
    Dot,

    #[token("..")]
    DotDot,

    #[token(",")]
    Comma,

    #[token(";")]
    Semicolon,

    #[token("+")]
    Plus,

    #[token("-")]
    Minus,

    #[token("*")]
    Mul,

    #[token("/")]
    Div,

    #[token("&")]
    And,

    #[token("|")]
    Or,

    #[token("^")]
    Xor,

    #[token("&&")]
    BAnd,

    #[token("||")]
    BOr,

    #[token("!")]
    Not,

    #[token("%")]
    Mod,

    #[token("=")]
    Assign,

    #[token("==")]
    Equals,

    #[token("!=")]
    NotEquals,

    #[token("<")]
    Less,

    #[token("<=")]
    LessEq,

    #[token(">")]
    Greater,

    #[token(">=")]
    GreaterEq,

    #[token("fn")]
    Fn,

    #[token("return")]
    Return,

    #[token("for")]
    For,

    #[token("in")]
    In,

    #[token("if")]
    If,

    #[token("else")]
    Else,

    #[token("box")]
    Box,

    #[token("wire")]
    Wire,

    #[token("head")]
    Head,

    #[token("tail")]
    Tail,

    #[token("delete")]
    Delete,

    #[token("forward")]
    Forward,

    #[token("back")]
    Back,

    #[token("left")]
    Left,

    #[token("right")]
    Right,

    #[token("up")]
    Up,

    #[token("down")]
    Down,

    #[token("look")]
    Look,

    #[token("roll")]
    Roll,

    #[token("true")]
    True,

    #[token("false")]
    False,

    #[regex("[a-zA-Z_][a-zA-Z0-9_]*")]
    IdentLiteral(&'input str),

    #[regex("[0-9][0-9_]*")]
    #[regex("0x[0-9a-fA-F_]+")]
    #[regex("0o[0-7_]+")]
    #[regex("0b[01_]+")]
    IntegerLiteral(&'input str),
}

impl<'input> Token<'input> {
    fn to_str(&self) -> &'input str {
        match self {
            Token::BraceOpen => "{",
            Token::BraceClose => "}",
            Token::ParOpen => "(",
            Token::ParClose => ")",
            Token::BracketOpen => "[",
            Token::BracketClose => "]",
            Token::Semicolon => ";",
            Token::Dot => ".",
            Token::DotDot => "..",
            Token::Comma => ",",
            Token::Plus => "+",
            Token::Minus => "-",
            Token::Mul => "*",
            Token::Div => "/",
            Token::Mod => "%",
            Token::And => "&",
            Token::Or => "|",
            Token::Xor => "^",
            Token::BAnd => "&&",
            Token::BOr => "||",
            Token::Not => "!",
            Token::Assign => "=",
            Token::Equals => "==",
            Token::NotEquals => "!=",
            Token::Less => "<",
            Token::LessEq => "<=",
            Token::Greater => ">",
            Token::GreaterEq => ">=",
            Token::Fn => "fn",
            Token::Return => "return",
            Token::For => "for",
            Token::In => "in",
            Token::If => "if",
            Token::Else => "else",
            Token::Box => "box",
            Token::Wire => "wire",
            Token::Head => "head",
            Token::Tail => "tail",
            Token::Delete => "delete",
            Token::Forward => "forward",
            Token::Back => "back",
            Token::Left => "left",
            Token::Right => "right",
            Token::Up => "up",
            Token::Down => "down",
            Token::Look => "look",
            Token::Roll => "roll",
            Token::True => "true",
            Token::False => "false",
            Token::IdentLiteral(s) => s,
            Token::IntegerLiteral(s) => s,
        }
    }
}

impl std::fmt::Display for Token<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_str().fmt(f)
    }
}

pub struct Lexer<'input> {
    logos: logos::Lexer<'input, Token<'input>>,
    pub errors: Vec<LexicalError>,
}

impl<'input> Iterator for Lexer<'input> {
    type Item = (ByteIndex, Token<'input>, ByteIndex);
    fn next(&mut self) -> Option<Self::Item> {
        let token = loop {
            match self.logos.next()? {
                Ok(token) => break token,
                Err(()) => {
                    self.errors
                        .push(LexicalError::new("Invalid token", self.span()));
                }
            }
        };
        let span = self.span();
        Some((span.start(), token, span.end()))
    }
}

impl<'input> Lexer<'input> {
    pub fn new(input: &'input str) -> Lexer<'input> {
        Self {
            logos: logos::Lexer::new(input),
            errors: Vec::new(),
        }
    }

    fn span(&self) -> Span {
        let span = self.logos.span();
        Span::new(
            u32::try_from(span.start).unwrap(),
            u32::try_from(span.end).unwrap(),
        )
    }
}
