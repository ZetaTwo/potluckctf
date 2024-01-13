use std::collections::HashMap;

use codespan::Span;
use glam::IVec3;
use map::{Map, Tile};

use crate::{Block, ErrorCtx, Expr, Ident, Program, Statement, StatementKind};

#[derive(Copy, Clone, Debug)]
pub struct Direction {
    forward: IVec3,
    left: IVec3,
    up: IVec3,
}

impl Default for Direction {
    fn default() -> Self {
        Self {
            forward: IVec3::Z,
            left: IVec3::X,
            up: IVec3::Y,
        }
    }
}

impl Direction {
    fn forward(&self) -> IVec3 {
        self.forward
    }

    fn back(&self) -> IVec3 {
        -self.forward
    }

    fn left(&self) -> IVec3 {
        self.left
    }

    fn right(&self) -> IVec3 {
        -self.left
    }

    fn up(&self) -> IVec3 {
        self.up
    }

    fn down(&self) -> IVec3 {
        -self.up
    }

    fn look_left(&self) -> Direction {
        let mut res = *self;
        (res.forward, res.left) = (res.left, -res.forward);
        res
    }

    fn look_right(&self) -> Direction {
        let mut res = *self;
        (res.forward, res.left) = (-res.left, res.forward);
        res
    }

    fn look_back(&self) -> Direction {
        let mut res = *self;
        (res.forward, res.left) = (-res.forward, -res.left);
        res
    }

    fn look_up(&self) -> Direction {
        let mut res = *self;
        (res.forward, res.up) = (res.up, -res.forward);
        res
    }

    fn look_down(&self) -> Direction {
        let mut res = *self;
        (res.forward, res.up) = (-res.up, res.forward);
        res
    }

    fn roll_left(&self) -> Direction {
        let mut res = *self;
        (res.left, res.up) = (-res.up, res.left);
        res
    }

    fn roll_right(&self) -> Direction {
        let mut res = *self;
        (res.left, res.up) = (res.up, -res.left);
        res
    }
}

impl Program {
    pub fn interpret(
        &self,
        map: &mut Map,
        position: &mut IVec3,
        direction: &mut Direction,
        error_ctx: &mut ErrorCtx,
    ) -> Result<(), ()> {
        self.interpret_function(
            "main",
            map,
            Vec::new(),
            position,
            direction,
            error_ctx,
            None,
        )?;
        Ok(())
    }

    pub fn interpret_function(
        &self,
        function_name: &str,
        map: &mut Map,
        args: Vec<Value>,
        position: &mut IVec3,
        direction: &mut Direction,
        error_ctx: &mut ErrorCtx,
        caller_span: Option<Span>,
    ) -> Result<Value, ()> {
        let Some(f) = self.fns.get(function_name) else {
            if let Some(caller_span) = caller_span {
                error_ctx.emit_error_simple(
                    caller_span,
                    &format!("Function `{function_name}` does not exist"),
                    None,
                );
            } else {
                error_ctx.emit_error(
                    &format!("Function `{function_name}` does not exist"),
                    Vec::new(),
                );
            }
            return Err(());
        };

        let mut state = Variables::default();
        let args_len = args.len();
        let mut fn_arg_count = 0;

        if let Some(fn_args) = &f.args {
            fn_arg_count = fn_args.more.len() + 1;
            for (i, v) in std::iter::once(&fn_args.first)
                .chain(fn_args.more.iter().map(|(_, i)| i))
                .zip(args)
            {
                state.insert(error_ctx, i, v)?;
            }
        }

        if args_len != fn_arg_count {
            if let Some(caller_span) = caller_span {
                error_ctx.emit_error_simple(
                    caller_span,
                    &format!(
                        "Function `{function_name}` takes {fn_arg_count} arguments, but called with {args_len}",
                    ),
                    None,
                );
            } else {
                error_ctx.emit_error(
                    &format!(
                        "Function `{function_name}` takes {fn_arg_count} arguments, but called with {args_len}",
                    ),
                    Vec::new(),
                );
            }
            return Err(());
        }

        let value = f
            .block
            .interpret(self, map, &mut state, position, direction, error_ctx)?;

        Ok(value.unwrap_or(Value::Tuple(Vec::new())))
    }
}

impl Block {
    fn interpret(
        &self,
        program: &Program,
        map: &mut Map,
        state: &mut Variables,
        position: &mut IVec3,
        direction: &mut Direction,
        error_ctx: &mut ErrorCtx,
    ) -> Result<Option<Value>, ()> {
        for s in &self.statements {
            if let Some(retval) =
                s.interpret(program, map, state, position, direction, error_ctx)?
            {
                return Ok(Some(retval));
            }
        }
        Ok(None)
    }
}

#[derive(Default)]
pub struct Variables {
    map: HashMap<String, Value>,
}

fn vec_to_tuple(vec: IVec3) -> Value {
    Value::Tuple(vec![
        Value::Int(vec.x as i128),
        Value::Int(vec.y as i128),
        Value::Int(vec.z as i128),
    ])
}

impl Variables {
    pub fn get(
        &self,
        position: &IVec3,
        direction: &Direction,
        error_ctx: &mut ErrorCtx,
        name: &Ident,
    ) -> Result<Value, ()> {
        if &name.name == "getpos" {
            Ok(vec_to_tuple(*position))
        } else if &name.name == "getdir" {
            Ok(Value::Tuple(vec![
                vec_to_tuple(direction.forward),
                vec_to_tuple(direction.left),
                vec_to_tuple(direction.up),
            ]))
        } else if let Some(value) = self.map.get(&name.name) {
            Ok(value.clone())
        } else {
            error_ctx.emit_error_simple(
                name.span,
                &format!("Undefined variable {}", &name.name),
                None,
            );
            Err(())
        }
    }

    pub fn insert(
        &mut self,
        error_ctx: &mut ErrorCtx,
        name: &Ident,
        value: Value,
    ) -> Result<(), ()> {
        if &name.name == "getpos" || &name.name == "getdir" {
            error_ctx.emit_error_simple(
                name.span,
                &format!("Cannot assign to variable {}", &name.name),
                None,
            );
            Err(())
        } else {
            self.map.insert(name.name.clone(), value);
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub enum Value {
    Int(i128),
    Tuple(Vec<Value>),
    Bool(bool),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Int(v) => v.fmt(f),
            Value::Tuple(t) => {
                write!(f, "(")?;
                let mut first = true;
                for v in t {
                    if !first {
                        write!(f, ", ")?;
                    }
                    first = false;
                    v.fmt(f)?;
                }
                write!(f, ")")?;
                Ok(())
            }
            Value::Bool(b) => b.fmt(f),
        }
    }
}

impl Expr {
    fn eval(
        &self,
        program: &Program,
        map: &mut Map,
        state: &Variables,
        position: &mut IVec3,
        direction: &mut Direction,
        error_ctx: &mut ErrorCtx,
    ) -> Result<Value, ()> {
        match &self.kind {
            crate::ExprKind::Variable(name) => state.get(position, direction, error_ctx, name),
            crate::ExprKind::Int(v) => Ok(Value::Int(v.value_interpreted)),
            crate::ExprKind::Plus { left, right, .. } => Ok(Value::Int(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    .wrapping_add(
                        right.eval_int(program, map, state, position, direction, error_ctx)?,
                    ),
            )),
            crate::ExprKind::Minus { left, right, .. } => Ok(Value::Int(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    .wrapping_sub(
                        right.eval_int(program, map, state, position, direction, error_ctx)?,
                    ),
            )),
            crate::ExprKind::Mul { left, right, .. } => Ok(Value::Int(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    .wrapping_mul(
                        right.eval_int(program, map, state, position, direction, error_ctx)?,
                    ),
            )),
            crate::ExprKind::Div { left, right, .. } => {
                let left = left.eval_int(program, map, state, position, direction, error_ctx)?;
                let right = right.eval_int(program, map, state, position, direction, error_ctx)?;
                if right == 0 {
                    error_ctx.emit_error_simple(self.span, "Divide by zero", None);
                    Err(())
                } else {
                    Ok(Value::Int(left.wrapping_div(right)))
                }
            }
            crate::ExprKind::Mod { left, right, .. } => {
                let left = left.eval_int(program, map, state, position, direction, error_ctx)?;
                let right = right.eval_int(program, map, state, position, direction, error_ctx)?;
                if right == 0 {
                    error_ctx.emit_error_simple(self.span, "Divide by zero", None);
                    Err(())
                } else {
                    Ok(Value::Int(left.wrapping_rem_euclid(right)))
                }
            }
            crate::ExprKind::And { left, right, .. } => Ok(Value::Int(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    & right.eval_int(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::Or { left, right, .. } => Ok(Value::Int(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    | right.eval_int(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::Xor { left, right, .. } => Ok(Value::Int(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    ^ right.eval_int(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::Call { name, args, .. } => {
                if &name.name == "log" {
                    let (filename, location) = error_ctx.lookup_location(name.span);
                    let saved_pos = *position;
                    let saved_direction = *direction;
                    let mut evaled = Vec::new();
                    if let Some(args) = args {
                        for arg in
                            std::iter::once(&*args.first).chain(args.more.iter().map(|(_, e)| e))
                        {
                            evaled.push((
                                arg.span,
                                arg.eval(program, map, state, position, direction, error_ctx)?,
                            ));
                        }
                    }

                    eprintln!("{filename}:{}:{}:", location.line, location.column);
                    eprintln!("    pos     = {}", saved_pos);
                    eprintln!("    forward = {}", saved_direction.forward);
                    eprintln!("    left    = {}", saved_direction.left);
                    eprintln!("    up      = {}", saved_direction.up);

                    for (span, value) in evaled {
                        let source = error_ctx
                            .files
                            .source_slice(error_ctx.file_id, span)
                            .unwrap();
                        eprintln!("    {} = {value}", source.trim());
                    }
                    eprintln!();
                    return Ok(Value::Tuple(vec![]));
                } else {
                    let mut evaluated_args = Vec::new();
                    if let Some(args) = args {
                        for arg in
                            std::iter::once(&*args.first).chain(args.more.iter().map(|(_, e)| e))
                        {
                            evaluated_args.push(
                                arg.eval(program, map, state, position, direction, error_ctx)?,
                            );
                        }
                    }
                    program.interpret_function(
                        &name.name,
                        map,
                        evaluated_args,
                        position,
                        direction,
                        error_ctx,
                        Some(self.span),
                    )
                }
            }
            crate::ExprKind::Tuple { init, rest, .. } => {
                let mut res = Vec::new();
                res.push(init.eval(program, map, state, position, direction, error_ctx)?);
                for (_, e) in rest {
                    res.push(e.eval(program, map, state, position, direction, error_ctx)?);
                }
                Ok(Value::Tuple(res))
            }
            crate::ExprKind::Paren { inner, .. } => {
                inner.eval(program, map, state, position, direction, error_ctx)
            }
            crate::ExprKind::Equals { left, right, .. } => Ok(Value::Bool(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    == right.eval_int(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::NotEquals { left, right, .. } => Ok(Value::Bool(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    != right.eval_int(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::Less { left, right, .. } => Ok(Value::Bool(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    < right.eval_int(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::LessEq { left, right, .. } => Ok(Value::Bool(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    <= right.eval_int(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::Greater { left, right, .. } => Ok(Value::Bool(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    > right.eval_int(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::GreaterEq { left, right, .. } => Ok(Value::Bool(
                left.eval_int(program, map, state, position, direction, error_ctx)?
                    >= right.eval_int(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::BAnd { left, right, .. } => Ok(Value::Bool(
                left.eval_bool(program, map, state, position, direction, error_ctx)?
                    && right.eval_bool(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::BOr { left, right, .. } => Ok(Value::Bool(
                left.eval_bool(program, map, state, position, direction, error_ctx)?
                    || right.eval_bool(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::Not { expr, .. } => Ok(Value::Bool(
                !expr.eval_bool(program, map, state, position, direction, error_ctx)?,
            )),
            crate::ExprKind::Bool(bool) => Ok(Value::Bool(*bool)),
        }
    }

    fn eval_int(
        &self,
        program: &Program,
        map: &mut Map,
        state: &Variables,
        position: &mut IVec3,
        direction: &mut Direction,
        error_ctx: &mut ErrorCtx,
    ) -> Result<i128, ()> {
        match self.eval(program, map, state, position, direction, error_ctx)? {
            Value::Bool(_) => {
                error_ctx.emit_error_simple(
                    self.span,
                    &format!("Expected an integer, not a bool"),
                    None,
                );
                Err(())
            }
            Value::Int(v) => Ok(v),
            Value::Tuple(_) => {
                error_ctx.emit_error_simple(
                    self.span,
                    &format!("Expected an integer, not a tuple"),
                    None,
                );
                Err(())
            }
        }
    }

    fn eval_bool(
        &self,
        program: &Program,
        map: &mut Map,
        state: &Variables,
        position: &mut IVec3,
        direction: &mut Direction,
        error_ctx: &mut ErrorCtx,
    ) -> Result<bool, ()> {
        match self.eval(program, map, state, position, direction, error_ctx)? {
            Value::Bool(b) => Ok(b),
            Value::Int(_) => {
                error_ctx.emit_error_simple(
                    self.span,
                    &format!("Expected a bool, not an integer"),
                    None,
                );
                Err(())
            }
            Value::Tuple(_) => {
                error_ctx.emit_error_simple(
                    self.span,
                    &format!("Expected a bool, not a tuple"),
                    None,
                );
                Err(())
            }
        }
    }
}

impl Statement {
    fn interpret(
        &self,
        program: &Program,
        map: &mut Map,
        state: &mut Variables,
        position: &mut IVec3,
        direction: &mut Direction,
        error_ctx: &mut ErrorCtx,
    ) -> Result<Option<Value>, ()> {
        match &self.kind {
            StatementKind::Box { .. } => {
                map.boxes.insert(*position);
                map.nodes.remove(position);
            }
            StatementKind::Wire { .. } => {
                map.nodes.insert(*position, Tile::Wire);
                map.boxes.remove(position);
            }
            StatementKind::Head { .. } => {
                map.nodes.insert(*position, Tile::ElectronHead);
                map.boxes.remove(position);
            }
            StatementKind::Tail { .. } => {
                map.nodes.insert(*position, Tile::ElectronTail);
                map.boxes.remove(position);
            }
            StatementKind::Delete { .. } => {
                map.nodes.remove(position);
                map.boxes.remove(position);
            }
            StatementKind::Forward { value, .. } => {
                let value = if let Some(value) = value {
                    value.eval_int(program, map, state, position, direction, error_ctx)? as i32
                } else {
                    1
                };
                *position += direction.forward() * value;
            }
            StatementKind::Back { value, .. } => {
                let value = if let Some(value) = value {
                    value.eval_int(program, map, state, position, direction, error_ctx)? as i32
                } else {
                    1
                };
                *position += direction.back() * value;
            }
            StatementKind::Left { value, .. } => {
                let value = if let Some(value) = value {
                    value.eval_int(program, map, state, position, direction, error_ctx)? as i32
                } else {
                    1
                };
                *position += direction.left() * value;
            }
            StatementKind::Right { value, .. } => {
                let value = if let Some(value) = value {
                    value.eval_int(program, map, state, position, direction, error_ctx)? as i32
                } else {
                    1
                };
                *position += direction.right() * value;
            }
            StatementKind::Up { value, .. } => {
                let value = if let Some(value) = value {
                    value.eval_int(program, map, state, position, direction, error_ctx)? as i32
                } else {
                    1
                };

                *position += direction.up() * value;
            }
            StatementKind::Down { value, .. } => {
                let value = if let Some(value) = value {
                    value.eval_int(program, map, state, position, direction, error_ctx)? as i32
                } else {
                    1
                };
                *position += direction.down() * value;
            }
            StatementKind::LookLeft { .. } => {
                *direction = direction.look_left();
            }
            StatementKind::LookRight { .. } => {
                *direction = direction.look_right();
            }
            StatementKind::LookBack { .. } => {
                *direction = direction.look_back();
            }
            StatementKind::LookUp { .. } => {
                *direction = direction.look_up();
            }
            StatementKind::LookDown { .. } => {
                *direction = direction.look_down();
            }
            StatementKind::RollLeft { .. } => {
                *direction = direction.roll_left();
            }
            StatementKind::RollRight { .. } => {
                *direction = direction.roll_right();
            }
            StatementKind::Block(block) => {
                if let Some(retval) = block.interpret(
                    program,
                    map,
                    state,
                    &mut position.clone(),
                    &mut direction.clone(),
                    error_ctx,
                )? {
                    return Ok(Some(retval));
                }
            }
            StatementKind::Assign { left, right, .. } => {
                let right = right.eval(program, map, state, position, direction, error_ctx)?;
                match (left, right) {
                    (crate::AssignTarget::Variable(i), right) => {
                        state.insert(error_ctx, i, right)?;
                    }
                    (crate::AssignTarget::Tuple { .. }, Value::Int(_)) => {
                        error_ctx.emit_error_simple(
                            self.span,
                            &format!("Cannot assign an integer to a tuple"),
                            None,
                        );
                        return Err(());
                    }
                    (crate::AssignTarget::Tuple { .. }, Value::Bool(_)) => {
                        error_ctx.emit_error_simple(
                            self.span,
                            &format!("Cannot assign a bool to a tuple"),
                            None,
                        );
                        return Err(());
                    }
                    (crate::AssignTarget::Tuple { init, rest, .. }, Value::Tuple(t)) => {
                        if rest.len() + 1 != t.len() {
                            error_ctx.emit_error_simple(
                                self.span,
                                &format!("Pattern on the left has length {}, but right side is length {}", rest.len() + 1, t.len()),
                                None,
                            );
                            return Err(());
                        }
                        for (name, value) in std::iter::once(init)
                            .chain(rest.iter().map(|(_, i)| i))
                            .zip(t)
                        {
                            state.insert(error_ctx, name, value)?;
                        }
                    }
                }
            }
            StatementKind::For {
                var,
                start,
                end,
                block,
                ..
            } => {
                let start = start.eval_int(program, map, state, position, direction, error_ctx)?;
                let end = end.eval_int(program, map, state, position, direction, error_ctx)?;
                for i in start..end {
                    state.insert(error_ctx, var, Value::Int(i))?;
                    if let Some(retval) =
                        block.interpret(program, map, state, position, direction, error_ctx)?
                    {
                        return Ok(Some(retval));
                    }
                }
            }
            StatementKind::Expr(e) => {
                e.eval(program, map, state, position, direction, error_ctx)?;
            }
            StatementKind::Return { expr, .. } => {
                let value = expr.eval(program, map, state, position, direction, error_ctx)?;
                return Ok(Some(value));
            }
            StatementKind::If {
                expr,
                block,
                elifs,
                else_,
                ..
            } => {
                if expr.eval_bool(program, map, state, position, direction, error_ctx)? {
                    return block.interpret(program, map, state, position, direction, error_ctx);
                }
                for elif in elifs {
                    if elif
                        .expr
                        .eval_bool(program, map, state, position, direction, error_ctx)?
                    {
                        return elif
                            .block
                            .interpret(program, map, state, position, direction, error_ctx);
                    }
                }
                if let Some(else_) = else_ {
                    return else_
                        .block
                        .interpret(program, map, state, position, direction, error_ctx);
                }
            }
        }
        Ok(None)
    }
}
