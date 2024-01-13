mod ast;
mod error;
pub mod interpret;
mod lexer;
lalrpop_util::lalrpop_mod!(grammar, "/grammar.rs");
mod grammar_helper;

use std::ffi::OsString;

pub use ast::*;

use codespan::{FileId, Files, Location, Span};
use codespan_reporting::{
    diagnostic::{Diagnostic, Label, LabelStyle},
    term::{
        self,
        termcolor::{BufferedStandardStream, ColorChoice},
        Config,
    },
};

pub struct ErrorCtx {
    stream: BufferedStandardStream,
    config: Config,
    files: Files<String>,
    file_id: FileId,
    has_error: bool,
}

impl ErrorCtx {
    pub fn new(path: impl Into<OsString>, input: String) -> Self {
        let color_choice = if atty::is(atty::Stream::Stderr) {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        };
        let mut files = Files::default();
        let file_id = files.add(path, input);
        Self {
            stream: BufferedStandardStream::stderr(color_choice),

            config: Config::default(),
            files,
            file_id,
            has_error: false,
        }
    }

    pub fn lookup_location(&self, span: Span) -> (String, Location) {
        (
            self.files.name(self.file_id).to_string_lossy().to_string(),
            self.files.location(self.file_id, span.start()).unwrap(),
        )
    }

    pub fn emit_error_simple(&mut self, span: Span, message: &str, label_message: Option<&str>) {
        let mut label = Label::new(
            LabelStyle::Primary,
            self.file_id,
            span.start().into()..span.end().into(),
        );
        if let Some(label_message) = label_message {
            label = label.with_message(label_message);
        }
        let labels = vec![label];
        self.emit_error(message, labels);
    }

    pub fn emit_error(&mut self, message: &str, labels: Vec<Label<FileId>>) {
        self.has_error = true;
        term::emit(
            &mut self.stream,
            &self.config,
            &self.files,
            &Diagnostic::error()
                .with_message(message)
                .with_labels(labels),
        )
        .unwrap();
    }
}

fn get_span<T>(
    error: &lalrpop_util::ParseError<codespan::ByteIndex, T, crate::error::LexicalError>,
) -> Span {
    match error {
        lalrpop_util::ParseError::InvalidToken { location } => Span::new(*location, *location),
        lalrpop_util::ParseError::UnrecognizedEof { location, .. } => {
            Span::new(*location, *location)
        }
        lalrpop_util::ParseError::UnrecognizedToken { token, .. } => Span::new(token.0, token.2),
        lalrpop_util::ParseError::ExtraToken { token } => Span::new(token.0, token.2),
        lalrpop_util::ParseError::User { error } => error.span,
    }
}

pub fn parse_str(error_ctx: &mut ErrorCtx) -> Result<Program, ()> {
    let source = error_ctx.files.source(error_ctx.file_id).clone();
    let mut lexer = crate::lexer::Lexer::new(&source);
    let program = crate::grammar::ProgramParser::new().parse(error_ctx, &mut lexer);

    match program {
        Ok(program) if lexer.errors.is_empty() && !error_ctx.has_error => {
            return Ok(program);
        }
        Ok(_) => (),
        Err(e) => {
            error_ctx.emit_error_simple(get_span(&e), &format!("{e}"), None);
        }
    }
    for e in lexer.errors {
        error_ctx.emit_error_simple(e.span, &format!("{e}"), None);
    }

    Err(())
}
