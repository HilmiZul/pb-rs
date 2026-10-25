//! Minimal filter-expression parser (`tools/search/filter.go`).
//!
//! This is a *partial* port: it handles comparisons (`=`, `!=`, `>`, `>=`,
//! `<`, `<=`, `~`, `!~`), logical `&&`/`||`, parentheses, field references,
//! literals (`'str'`, numbers, `true`/`false`/`null`) and a handful of
//! functions (`lower`, `upper`, `trim`, `length`). Relation traversal
//! (`a.b`), `@request.auth`/`@collection` macros, `@now`/`@rowid` and the
//! multi-match subqueries are NOT implemented yet and are tracked for M3b.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cmp {
        left: Box<Expr>,
        op: CmpOp,
        right: Box<Expr>,
    },
    Field(String),
    Literal(Literal),
    Func {
        name: String,
        args: Vec<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    NotContains,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
}

impl fmt::Display for CmpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CmpOp::Eq => "=",
            CmpOp::Ne => "!=",
            CmpOp::Gt => ">",
            CmpOp::Gte => ">=",
            CmpOp::Lt => "<",
            CmpOp::Lte => "<=",
            CmpOp::Contains => "~",
            CmpOp::NotContains => "!~",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

// ---------- Lexer----------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Eof,
    Ident(String),
    String(String),
    Number(f64),
    Op(String), // multi-char or single-char operators
    LParen,
    RParen,
    Comma,
}

fn lex(input: &str) -> Result<Vec<Tok>, ParseError> {
    let chars: Vec<char> = input.chars().collect();
    let mut pos = 0;
    let mut out = Vec::new();
    while pos < chars.len() {
        let c = chars[pos];
        if c.is_whitespace() {
            pos += 1;
            continue;
        }
        if c == '(' {
            out.push(Tok::LParen);
            pos += 1;
            continue;
        }
        if c == ')' {
            out.push(Tok::RParen);
            pos += 1;
            continue;
        }
        if c == ',' {
            out.push(Tok::Comma);
            pos += 1;
            continue;
        }
        // operators
        if c == '!' {
            if pos + 1 < chars.len() && chars[pos + 1] == '=' {
                out.push(Tok::Op("!=".into()));
                pos += 2;
                continue;
            }
            if pos + 1 < chars.len() && chars[pos + 1] == '~' {
                out.push(Tok::Op("!~".into()));
                pos += 2;
                continue;
            }
            out.push(Tok::Op("!".into()));
            pos += 1;
            continue;
        }
        if c == '=' {
            out.push(Tok::Op("=".into()));
            pos += 1;
            continue;
        }
        if c == '>' {
            if pos + 1 < chars.len() && chars[pos + 1] == '=' {
                out.push(Tok::Op(">=".into()));
                pos += 2;
                continue;
            }
            out.push(Tok::Op(">".into()));
            pos += 1;
            continue;
        }
        if c == '<' {
            if pos + 1 < chars.len() && chars[pos + 1] == '=' {
                out.push(Tok::Op("<=".into()));
                pos += 2;
                continue;
            }
            out.push(Tok::Op("<".into()));
            pos += 1;
            continue;
        }
        if c == '~' {
            out.push(Tok::Op("~".into()));
            pos += 1;
            continue;
        }
        if c == '&' && pos + 1 < chars.len() && chars[pos + 1] == '&' {
            out.push(Tok::Op("&&".into()));
            pos += 2;
            continue;
        }
        if c == '|' && pos + 1 < chars.len() && chars[pos + 1] == '|' {
            out.push(Tok::Op("||".into()));
            pos += 2;
            continue;
        }
        // string literal
        if c == '\'' || c == '"' {
            let quote = c;
            pos += 1;
            let mut s = String::new();
            while pos < chars.len() && chars[pos] != quote {
                if chars[pos] == '\\' {
                    pos += 1;
                    if pos < chars.len() {
                        s.push(chars[pos]);
                        pos += 1;
                    }
                } else {
                    s.push(chars[pos]);
                    pos += 1;
                }
            }
            if pos >= chars.len() {
                return Err(ParseError("unterminated string".into()));
            }
            pos += 1;
            out.push(Tok::String(s));
            continue;
        }
        // number
        if c.is_ascii_digit() || (c == '-' && pos + 1 < chars.len() && chars[pos + 1].is_ascii_digit()) {
            let start = pos;
            if chars[pos] == '-' {
                pos += 1;
            }
            while pos < chars.len() && (chars[pos].is_ascii_digit() || chars[pos] == '.') {
                pos += 1;
            }
            let s: String = chars[start..pos].iter().collect();
            let n: f64 = s.parse().map_err(|_| ParseError(format!("bad number: {s}")))?;
            out.push(Tok::Number(n));
            continue;
        }
        // identifier
        if c.is_alphabetic() || c == '_' || c == '@' {
            let start = pos;
            while pos < chars.len()
                && (chars[pos].is_alphanumeric() || chars[pos] == '_' || chars[pos] == '.' || chars[pos] == '@')
            {
                pos += 1;
            }
            let ident: String = chars[start..pos].iter().collect();
            // keywords
            match ident.as_str() {
                "true" => out.push(Tok::Ident("__true__".into())),
                "false" => out.push(Tok::Ident("__false__".into())),
                "null" => out.push(Tok::Ident("__null__".into())),
                _ => out.push(Tok::Ident(ident)),
            }
            continue;
        }
        return Err(ParseError(format!("unexpected char: {c}")));
    }
    out.push(Tok::Eof);
    Ok(out)
}

// ----------Parser----------

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        self.toks.get(self.pos).unwrap_or(&Tok::Eof)
    }
    fn advance(&mut self) {
        if self.pos < self.toks.len() {
            self.pos += 1;
        }
    }
    fn parse(&mut self) -> Result<Expr, ParseError> {
        let e = self.or_expr()?;
        if !matches!(self.peek(), Tok::Eof) {
            return Err(ParseError("trailing tokens".into()));
        }
        Ok(e)
    }
    fn or_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.and_expr()?;
        while let Tok::Op(op) = self.peek() {
            if op != "||" {
                break;
            }
            self.advance();
            let right = self.and_expr()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn and_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.not_expr()?;
        while let Tok::Op(op) = self.peek() {
            if op != "&&" {
                break;
            }
            self.advance();
            let right = self.not_expr()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn not_expr(&mut self) -> Result<Expr, ParseError> {
        if let Tok::Op(op) = self.peek() {
            if op == "!" {
                self.advance();
                let e = self.not_expr()?;
                return Ok(Expr::Not(Box::new(e)));
            }
        }
        self.cmp_expr()
    }
    fn cmp_expr(&mut self) -> Result<Expr, ParseError> {
        let left = self.primary()?;
        if let Tok::Op(op) = self.peek() {
            let cmp = match op.as_str() {
                "=" => Some(CmpOp::Eq),
                "!=" => Some(CmpOp::Ne),
                ">" => Some(CmpOp::Gt),
                ">=" => Some(CmpOp::Gte),
                "<" => Some(CmpOp::Lt),
                "<=" => Some(CmpOp::Lte),
                "~" => Some(CmpOp::Contains),
                "!~" => Some(CmpOp::NotContains),
                _ => None,
            };
            if let Some(cmp) = cmp {
                self.advance();
                let right = self.primary()?;
                return Ok(Expr::Cmp {
                    left: Box::new(left),
                    op: cmp,
                    right: Box::new(right),
                });
            }
        }
        Ok(left)
    }
    fn primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek().clone() {
            Tok::LParen => {
                self.advance();
                let e = self.or_expr()?;
                if !matches!(self.peek(), Tok::RParen) {
                    return Err(ParseError("expected )".into()));
                }
                self.advance();
                Ok(e)
            }
            Tok::Ident(name) => {
                self.advance();
                // function call?
                if matches!(self.peek(), Tok::LParen) {
                    self.advance();
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Tok::RParen) {
                        args.push(self.or_expr()?);
                        while matches!(self.peek(), Tok::Comma) {
                            self.advance();
                            args.push(self.or_expr()?);
                        }
                    }
                    if !matches!(self.peek(), Tok::RParen) {
                        return Err(ParseError("expected )".into()));
                    }
                    self.advance();
                    // keywords
                    match name.as_str() {
                        "__true__" => Ok(Expr::Literal(Literal::Bool(true))),
                        "__false__" => Ok(Expr::Literal(Literal::Bool(false))),
                        "__null__" => Ok(Expr::Literal(Literal::Null)),
                        _ => Ok(Expr::Func { name, args }),
                    }
                } else {
                    match name.as_str() {
                        "__true__" => Ok(Expr::Literal(Literal::Bool(true))),
                        "__false__" => Ok(Expr::Literal(Literal::Bool(false))),
                        "__null__" => Ok(Expr::Literal(Literal::Null)),
                        _ => Ok(Expr::Field(name)),
                    }
                }
            }
            Tok::String(s) => {
                self.advance();
                Ok(Expr::Literal(Literal::String(s)))
            }
            Tok::Number(n) => {
                self.advance();
                Ok(Expr::Literal(Literal::Number(n)))
            }
            _ => Err(ParseError(format!("unexpected token: {:?}", self.peek()))),
        }
    }
}

pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let toks = lex(input)?;
    let mut p = Parser { toks, pos: 0 };
    p.parse()
}

// ----------SQL generation----------

pub struct SqlFilter {
    pub sql: String,
    pub params: Vec<serde_json::Value>,
}

/// Build a SQL WHERE clause from a filter expression.
/// `allowed_fields` is the set of valid field names (for validation).
pub fn build_sql(expr: &Expr, allowed_fields: &[String]) -> Result<SqlFilter, ParseError> {
    let mut ctx = BuildCtx {
        params: Vec::new(),
        allowed: allowed_fields,
    };
    let sql = build_expr(expr, &mut ctx)?;
    Ok(SqlFilter { sql, params: ctx.params })
}

struct BuildCtx<'a> {
    params: Vec<serde_json::Value>,
    allowed: &'a [String],
}

fn build_expr(expr: &Expr, ctx: &mut BuildCtx<'_>) -> Result<String, ParseError> {
    match expr {
        Expr::Or(a, b) => {
            let la = build_expr(a, ctx)?;
            let lb = build_expr(b, ctx)?;
            Ok(format!("({} OR {})", la, lb))
        }
        Expr::And(a, b) => {
            let la = build_expr(a, ctx)?;
            let lb = build_expr(b, ctx)?;
            Ok(format!("({} AND {})", la, lb))
        }
        Expr::Not(e) => {
            let inner = build_expr(e, ctx)?;
            Ok(format!("NOT ({})", inner))
        }
        Expr::Cmp { left, op, right } => build_cmp(left, *op, right, ctx),
        Expr::Field(name) => {
            if !ctx.allowed.iter().any(|f| f == name) && name != "id" {
                return Err(ParseError(format!("unknown field: {name}")));
            }
            // quote identifier
            Ok(format!("\"{}\"", name.replace('"', "\"\"")))
        }
        Expr::Literal(lit) => match lit {
            Literal::Null => Ok("NULL".into()),
            Literal::Bool(b) => {
                ctx.params.push(serde_json::Value::Bool(*b));
                Ok("?".into())
            }
            Literal::Number(n) => {
                ctx.params.push(serde_json::json!(*n));
                Ok("?".into())
            }
            Literal::String(s) => {
                ctx.params.push(serde_json::Value::String(s.clone()));
                Ok("?".into())
            }
        },
        Expr::Func { name, args } => {
            let mut parts = Vec::new();
            for a in args {
                parts.push(build_expr(a, ctx)?);
            }
            // map function names to SQL
            let sql_name = match name.to_lowercase().as_str() {
                "lower" => "lower",
                "upper" => "upper",
                "trim" => "trim",
                "length" => "length",
                _ => name.as_str(),
            };
            Ok(format!("{}({})", sql_name, parts.join(", ")))
        }
    }
}

fn build_cmp(left: &Expr, op: CmpOp, right: &Expr, ctx: &mut BuildCtx<'_>) -> Result<String, ParseError> {
    // Handle null comparisons
    if let Expr::Literal(Literal::Null) = right {
        let l = build_expr(left, ctx)?;
        return Ok(match op {
            CmpOp::Eq => format!("{} IS NULL", l),
            CmpOp::Ne => format!("{} IS NOT NULL", l),
            _ => format!("{} {} NULL", l, op),
        });
    }
    let l = build_expr(left, ctx)?;
    let r = build_expr(right, ctx)?;
    match op {
        CmpOp::Contains => Ok(format!("{} LIKE '%' || {} || '%'", l, r)),
        CmpOp::NotContains => Ok(format!("{} NOT LIKE '%' || {} || '%'", l, r)),
        _ => Ok(format!("{} {} {}", l, op, r)),
    }
}

// Fix Contains: the right side pushed a param already; LIKE needs the param.
// Re-implement Contains properly:
// (handled above is wrong; redo below)
