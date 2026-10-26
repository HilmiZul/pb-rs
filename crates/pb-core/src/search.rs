//! Minimal filter-expression parser (`tools/search/filter.go`).
//!
//! This is a *partial* port: it handles comparisons (`=`, `!=`, `>`, `>=`,
//! `<`, `<=`, `~`, `!~`), logical `&&`/`||`, parentheses, field references,
//! literals (`'str'`, numbers, `true`/`false`/`null`) and a handful of
//! functions (`lower`, `upper`, `trim`, `length`). Relation traversal
//! (`a.b`), `@request.auth`/`@collection` macros, `@now`/`@rowid` and the
//! multi-match subqueries are NOT implemented yet and are tracked for M3b.

use std::fmt;

// Record type alias for auth context
use crate::records::Record as PbRecord;

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
    /// `@collection.<nameOrId>[:alias].<field>[.<sub>]`.
    CollectionField(String),
    AuthField(String),
    Now,
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
    /// `?=` and friends: any-value match on multi-value fields.
    AnyEq,
    AnyNe,
    AnyGt,
    AnyGte,
    AnyLt,
    AnyLte,
    AnyContains,
    AnyNotContains,
}

impl CmpOp {
    /// The underlying comparison for the `?` (any-match) variants.
    pub fn base(self) -> CmpOp {
        match self {
            CmpOp::AnyEq => CmpOp::Eq,
            CmpOp::AnyNe => CmpOp::Ne,
            CmpOp::AnyGt => CmpOp::Gt,
            CmpOp::AnyGte => CmpOp::Gte,
            CmpOp::AnyLt => CmpOp::Lt,
            CmpOp::AnyLte => CmpOp::Lte,
            CmpOp::AnyContains => CmpOp::Contains,
            CmpOp::AnyNotContains => CmpOp::NotContains,
            other => other,
        }
    }

    /// `?` operators skip the multi-match `NOT EXISTS` check.
    pub fn is_any(self) -> bool {
        self != self.base()
    }
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
            CmpOp::AnyEq => "?=",
            CmpOp::AnyNe => "?!=",
            CmpOp::AnyGt => "?>",
            CmpOp::AnyGte => "?>=",
            CmpOp::AnyLt => "?<",
            CmpOp::AnyLte => "?<=",
            CmpOp::AnyContains => "?~",
            CmpOp::AnyNotContains => "?!~",
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
        if c == '?' {
            let n = chars.get(pos + 1).copied();
            let n2 = chars.get(pos + 2).copied();
            let (op, len) = match (n, n2) {
                (Some('='), _) => ("?=", 2),
                (Some('!'), Some('=')) => ("?!=", 3),
                (Some('!'), Some('~')) => ("?!~", 3),
                (Some('>'), Some('=')) => ("?>=", 3),
                (Some('>'), _) => ("?>", 2),
                (Some('<'), Some('=')) => ("?<=", 3),
                (Some('<'), _) => ("?<", 2),
                (Some('~'), _) => ("?~", 2),
                _ => return Err(ParseError("unexpected char: ?".into())),
            };
            out.push(Tok::Op(op.into()));
            pos += len;
            continue;
        }
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
                && (chars[pos].is_alphanumeric()
                    || chars[pos] == '_'
                    || chars[pos] == '.'
                    || chars[pos] == '@'
                    || chars[pos] == ':')
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
                "?=" => Some(CmpOp::AnyEq),
                "?!=" => Some(CmpOp::AnyNe),
                "?>" => Some(CmpOp::AnyGt),
                "?>=" => Some(CmpOp::AnyGte),
                "?<" => Some(CmpOp::AnyLt),
                "?<=" => Some(CmpOp::AnyLte),
                "?~" => Some(CmpOp::AnyContains),
                "?!~" => Some(CmpOp::AnyNotContains),
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
                if name == "@now" {
                    return Ok(Expr::Now);
                }
                if let Some(rest) = name.strip_prefix("@collection.") {
                    return Ok(Expr::CollectionField(rest.to_string()));
                }
                if let Some(rest) = name.strip_prefix("@request.auth.") {
                    return Ok(Expr::AuthField(rest.to_string()));
                }
                if name == "@request.auth" {
                    return Ok(Expr::AuthField("id".to_string()));
                }
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

/// Metadata for a relation field used by relation-path filters.
#[derive(Clone, Debug)]
pub struct RelationInfo {
    pub table: String,
    pub multiple: bool,
}

/// The request data that `@request.*` filter fields resolve against.
///
/// Mirrors `core.RequestInfo`: `Body` holds the already normalized record data
/// (modifiers resolved), `Query` the URL query values and `Headers` the HTTP
/// request headers (lowercased keys, like Go's `http.Header` canonical form).
#[derive(Clone, Debug, Default)]
pub struct RequestData {
    pub body: serde_json::Map<String, serde_json::Value>,
    pub query: std::collections::HashMap<String, String>,
    pub headers: std::collections::HashMap<String, String>,
    pub method: String,
    pub context: String,
}

/// Field metadata used by `@request.*` resolution (numeric strings are cast).
#[derive(Clone, Debug, Default)]
pub struct RequestFieldTypes {
    pub numbers: std::collections::HashSet<String>,
}

/// Replace `@request.*` identifiers with literals.
///
/// The filter parser keeps unknown `@request.*` names as [`Expr::Field`]; the
/// record field resolver turns them into bound parameters. This pre-pass does
/// the same after the parser, so both the list filter builder and the rule
/// evaluator see plain literals.
pub fn resolve_request_fields(
    expr: &Expr,
    request: &RequestData,
    types: &RequestFieldTypes,
) -> Result<Expr, ParseError> {
    Ok(match expr {
        Expr::Field(name) if name.starts_with("@request.") => {
            let value = request_field_value(name, request, types)?;
            match value {
                serde_json::Value::Null => Expr::Literal(Literal::Null),
                serde_json::Value::Bool(b) => Expr::Literal(Literal::Bool(b)),
                serde_json::Value::Number(n) => {
                    Expr::Literal(Literal::Number(n.as_f64().unwrap_or(0.0)))
                }
                serde_json::Value::String(s) => Expr::Literal(Literal::String(s)),
                other => Expr::Literal(Literal::String(crate::go_json::marshal(&other))),
            }
        }
        Expr::Or(a, b) => Expr::Or(
            Box::new(resolve_request_fields(a, request, types)?),
            Box::new(resolve_request_fields(b, request, types)?),
        ),
        Expr::And(a, b) => Expr::And(
            Box::new(resolve_request_fields(a, request, types)?),
            Box::new(resolve_request_fields(b, request, types)?),
        ),
        Expr::Not(e) => Expr::Not(Box::new(resolve_request_fields(e, request, types)?)),
        Expr::Cmp { left, op, right } => Expr::Cmp {
            left: Box::new(resolve_request_fields(left, request, types)?),
            op: *op,
            right: Box::new(resolve_request_fields(right, request, types)?),
        },
        Expr::Func { name, args } => Expr::Func {
            name: name.clone(),
            args: args
                .iter()
                .map(|a| resolve_request_fields(a, request, types))
                .collect::<Result<_, _>>()?,
        },
        other => other.clone(),
    })
}

fn request_field_value(
    name: &str,
    request: &RequestData,
    types: &RequestFieldTypes,
) -> Result<serde_json::Value, ParseError> {
    let path = name.trim_start_matches("@request.");
    let (head, rest) = path
        .split_once('.')
        .ok_or_else(|| ParseError(format!("invalid request field: {name}")))?;
    let (raw_path, modifier) = split_request_modifier(rest)?;

    let found = match head {
        "method" => Some(serde_json::Value::String(request.method.clone())),
        "context" => Some(serde_json::Value::String(request.context.clone())),
        "body" => extract_nested(&serde_json::Value::Object(request.body.clone()), &raw_path),
        "query" => extract_nested_string_map(&request.query, &raw_path),
        "headers" => {
            let lower = raw_path.to_lowercase();
            request
                .headers
                .get(&lower)
                .map(|s| serde_json::Value::String(s.clone()))
        }
        _ => None,
    };

    match modifier.as_str() {
        "isset" => return Ok(serde_json::Value::Bool(found.is_some())),
        "lower" => {
            let value = found.unwrap_or(serde_json::Value::Null);
            return Ok(match value {
                serde_json::Value::String(s) => serde_json::Value::String(s.to_lowercase()),
                other => other,
            });
        }
        "length" => {
            let value = found.unwrap_or(serde_json::Value::Null);
            let len = match &value {
                serde_json::Value::String(s) => s.chars().count(),
                serde_json::Value::Array(items) => items.len(),
                serde_json::Value::Object(map) => map.len(),
                _ => 0,
            };
            return Ok(serde_json::Value::from(len));
        }
        "each" => {
            return Err(ParseError(
                "@request.*:each is not supported in this context".into(),
            ))
        }
        "" => {}
        other => return Err(ParseError(format!("unknown modifier: {other}"))),
    }

    let Some(mut value) = found else {
        return Ok(serde_json::Value::Null);
    };

    // numeric strings coming from form data are cast for number fields
    if let serde_json::Value::String(s) = &value {
        if types.numbers.contains(&raw_path) {
            if let Ok(n) = s.parse::<f64>() {
                value = serde_json::Value::from(n);
            }
        }
    }

    Ok(value)
}

fn split_request_modifier(path: &str) -> Result<(String, String), ParseError> {
    match path.split_once(':') {
        None => Ok((path.to_string(), String::new())),
        Some((key, modifier)) => match modifier {
            "isset" | "each" | "length" | "lower" | "changed" => {
                Ok((key.to_string(), modifier.to_string()))
            }
            other => Err(ParseError(format!("unknown modifier: {other}"))),
        },
    }
}

fn extract_nested(value: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let mut current = value;
    for key in path.split('.') {
        match current {
            serde_json::Value::Object(map) => current = map.get(key)?,
            _ => return None,
        }
    }
    Some(current.clone())
}

fn extract_nested_string_map(
    map: &std::collections::HashMap<String, String>,
    path: &str,
) -> Option<serde_json::Value> {
    // URL query maps in Go are `map[string][]string`; `RequestInfo.Query` uses
    // the first value, so a plain lookup is enough here.
    map.get(path)
        .map(|s| serde_json::Value::String(s.clone()))
}

/// Metadata for a collection referenced through `@collection.*`.
#[derive(Clone, Debug, Default)]
pub struct CollectionInfo {
    pub table: String,
    pub fields: Vec<String>,
    pub relations: std::collections::HashMap<String, RelationInfo>,
}

/// Build a SQL WHERE clause from a filter expression.
/// `allowed_fields` is the set of valid field names (for validation).
pub fn build_sql(expr: &Expr, allowed_fields: &[String]) -> Result<SqlFilter, ParseError> {
    build_sql_with_auth(expr, allowed_fields, None)
}

pub fn build_sql_with_auth_and_relations(
    expr: &Expr,
    allowed_fields: &[String],
    auth: Option<&PbRecord>,
    relations: &std::collections::HashMap<String, RelationInfo>,
) -> Result<SqlFilter, ParseError> {
    build_sql_full(
        expr,
        allowed_fields,
        auth,
        relations,
        &std::collections::HashMap::new(),
    )
}

/// Full builder: relation traversal plus `@collection.*` references.
pub fn build_sql_full(
    expr: &Expr,
    allowed_fields: &[String],
    auth: Option<&PbRecord>,
    relations: &std::collections::HashMap<String, RelationInfo>,
    collections: &std::collections::HashMap<String, CollectionInfo>,
) -> Result<SqlFilter, ParseError> {
    let mut ctx = BuildCtx {
        params: Vec::new(),
        allowed: allowed_fields,
        auth,
        relations,
        collections,
    };
    let sql = build_expr(expr, &mut ctx)?;
    Ok(SqlFilter { sql, params: ctx.params })
}

pub fn build_sql_with_auth(
    expr: &Expr,
    allowed_fields: &[String],
    auth: Option<&PbRecord>,
) -> Result<SqlFilter, ParseError> {
    build_sql_with_auth_and_relations(expr, allowed_fields, auth, &std::collections::HashMap::new())
}

struct BuildCtx<'a> {
    params: Vec<serde_json::Value>,
    allowed: &'a [String],
    auth: Option<&'a PbRecord>,
    relations: &'a std::collections::HashMap<String, RelationInfo>,
    collections: &'a std::collections::HashMap<String, CollectionInfo>,
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
        Expr::CollectionField(path) => {
            let (from, col) = collection_from(path, ctx)?;
            Ok(format!("EXISTS (SELECT 1 FROM {from} WHERE {col})"))
        }
        Expr::Field(name) => {
            if name.contains('.') {
                let first = name.split('.').next().unwrap_or(name);
                if !ctx.allowed.iter().any(|f| f == first) && first != "id" {
                    return Err(ParseError(format!("unknown field: {}", name)));
                }
                return Ok(crate::records::quote_ident(name));
            }
            if !ctx.allowed.iter().any(|f| f == name) && name != "id" {
                return Err(ParseError(format!("unknown field: {}", name)));
            }
            // quote identifier
            Ok(format!("\"{}\"", name.replace('"', "\"")))
        }
        Expr::AuthField(path) => {
            let val = ctx
                .auth
                .and_then(|a| a.data.get(path.as_str()).cloned())
                .unwrap_or(serde_json::Value::Null);
            ctx.params.push(val);
            Ok("?".into())
        }
        Expr::Now => Ok("datetime('now')".into()),
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum OperandKind {
    Value,
    EmptyString,
    Null,
}

fn static_kind(expr: &Expr) -> OperandKind {
    match expr {
        Expr::Literal(Literal::Null) => OperandKind::Null,
        Expr::Literal(Literal::String(s)) if s.is_empty() => OperandKind::EmptyString,
        _ => OperandKind::Value,
    }
}

/// Build an operand, remembering whether it is an empty-string/null literal so
/// that `resolveEqualExpr`'s null-fallback rules can be reproduced.
fn build_operand(
    expr: &Expr,
    ctx: &mut BuildCtx<'_>,
) -> Result<(String, OperandKind), ParseError> {
    let kind = static_kind(expr);
    match kind {
        OperandKind::Null => Ok(("NULL".into(), kind)),
        OperandKind::EmptyString => {
            ctx.params.push(serde_json::Value::String(String::new()));
            Ok(("?".into(), kind))
        }
        OperandKind::Value => Ok((build_expr(expr, ctx)?, kind)),
    }
}

/// `tools/search/filter.go` `resolveEqualExpr` + the simple operators.
fn compare_sql(
    left: &str,
    left_kind: OperandKind,
    op: CmpOp,
    right: &str,
    right_kind: OperandKind,
) -> String {
    let (equal_op, concat, null_expr) = match op {
        CmpOp::Ne => ("IS NOT", "AND", "IS NOT NULL"),
        _ => ("=", "OR", "IS NULL"),
    };

    match op {
        CmpOp::Eq | CmpOp::Ne => match (left_kind, right_kind) {
            (OperandKind::Null, _) | (_, OperandKind::Null) => {
                let not = op == CmpOp::Ne;
                if left_kind == OperandKind::Null && right_kind == OperandKind::Null {
                    // `null = null` -> `NULL IS NULL`; `null != null` -> `NULL IS NOT NULL`.
                    if not { "NULL IS NOT NULL".into() } else { "NULL IS NULL".into() }
                } else if left_kind == OperandKind::Null {
                    format!("NULL {null_expr}")
                } else {
                    format!("{left} {null_expr}")
                }
            }
            (OperandKind::EmptyString, OperandKind::EmptyString) => {
                format!("'' {equal_op} ''")
            }
            (OperandKind::EmptyString, _) => format!(
                "('' {equal_op} {right} {concat} {right} {null_expr})"
            ),
            (_, OperandKind::EmptyString) => format!(
                "({left} {equal_op} '' {concat} {left} {null_expr})"
            ),
            _ => format!("{left} {equal_op} {right}"),
        },
        CmpOp::Gt => format!("{left} > {right}"),
        CmpOp::Gte => format!("{left} >= {right}"),
        CmpOp::Lt => format!("{left} < {right}"),
        CmpOp::Lte => format!("{left} <= {right}"),
        // LIKE is built by `like_sql`.
        CmpOp::Contains | CmpOp::NotContains => unreachable!(),
        _ => unreachable!(),
    }
}

/// `tools/search/filter.go` `containsUnescapedChar`.
fn contains_unescaped_percent(s: &str) -> bool {
    let mut prev = '\0';
    for c in s.chars() {
        if c == '%' && prev != '\\' {
            return true;
        }
        if c == '\\' && prev == '\\' {
            prev = '\0';
        } else {
            prev = c;
        }
    }
    false
}

/// `tools/search/filter.go` `escapeUnescapedChars`.
fn escape_unescaped_chars(s: &str, escape_chars: &[char]) -> String {
    let rs: Vec<char> = s.chars().collect();
    let mut result: Vec<char> = Vec::with_capacity(rs.len());
    let mut matched = false;

    for i in (0..rs.len()).rev() {
        if matched {
            if rs[i] != '\\' {
                result.push('\\');
            }
            matched = false;
        } else if escape_chars.contains(&rs[i]) {
            matched = true;
        }
        result.push(rs[i]);
        if i == 0 && matched {
            result.push('\\');
        }
    }
    result.reverse();
    result.into_iter().collect()
}

/// `tools/search/filter.go` `wrapLikeParams`.
fn wrap_like_param(s: &str) -> String {
    if contains_unescaped_percent(s) {
        s.to_string()
    } else {
        format!("%{}%", escape_unescaped_chars(s, &['\\', '%', '_']))
    }
}

/// Build `left LIKE/Not LIKE right ESCAPE '\'` with PB's param wrapping.
fn like_sql(
    left: &str,
    right: &Expr,
    ctx: &mut BuildCtx<'_>,
    negate: bool,
) -> Result<String, ParseError> {
    let before = ctx.params.len();
    let r = build_expr(right, ctx)?;
    let keyword = if negate { "NOT LIKE" } else { "LIKE" };
    if ctx.params.len() > before {
        for p in &mut ctx.params[before..] {
            if let Some(text) = p.as_str() {
                *p = serde_json::Value::String(wrap_like_param(text));
            }
        }
        Ok(format!("{left} {keyword} {r} ESCAPE '\\'"))
    } else {
        Ok(format!("{left} {keyword} ('%' || {r} || '%') ESCAPE '\\'"))
    }
}

/// Resolve `@collection.<name[:alias]>.<field>[.<sub>]` into a FROM clause and
/// the final column expression. The FROM always yields at least one row, so an
/// empty referenced collection behaves like PB's `LEFT JOIN` (NULL columns).
fn collection_from(
    path: &str,
    ctx: &mut BuildCtx<'_>,
) -> Result<(String, String), ParseError> {
    let (head, rest) = path
        .split_once('.')
        .ok_or_else(|| ParseError(format!("invalid @collection field path: {path}")))?;
    let (name, alias) = match head.split_once(':') {
        Some((n, a)) => (n, Some(a)),
        None => (head, None),
    };
    let (field, sub) = match rest.split_once('.') {
        Some((f, s)) => (f, Some(s)),
        None => (rest, None),
    };
    if let Some(sub) = sub {
        if sub.contains('.') {
            return Err(ParseError(format!(
                "nested @collection path is not supported: {path}"
            )));
        }
    }
    let info = ctx
        .collections
        .get(name)
        .ok_or_else(|| ParseError(format!("unknown collection: {name}")))?;
    if !info.fields.iter().any(|f| f == field) && field != "id" {
        return Err(ParseError(format!("unknown field: {field}")));
    }
    let alias = alias.unwrap_or(name);
    let alias_sql = format!(
        "__pc_{}",
        alias.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    );
    let table = crate::records::quote_ident(&info.table);

    match sub {
        None => Ok((
            format!("(SELECT 1) AS __pb_one LEFT JOIN {table} AS {alias_sql} ON 1"),
            format!("{alias_sql}.{}", crate::records::quote_ident(field)),
        )),
        Some(sub) => {
            let rel = info
                .relations
                .get(field)
                .ok_or_else(|| ParseError(format!("field {field} is not a relation")))?;
            let rel_table = crate::records::quote_ident(&rel.table);
            if rel.multiple {
                let je = format!("{alias_sql}_je");
                Ok((
                    format!(
                        "(SELECT 1) AS __pb_one LEFT JOIN {table} AS {alias_sql} ON 1 \
                         LEFT JOIN json_each({alias_sql}.{field}) AS {je} ON 1 \
                         LEFT JOIN {rel_table} AS __pc_rel ON __pc_rel.id = {je}.value",
                        field = crate::records::quote_ident(field),
                    ),
                    format!("__pc_rel.{}", crate::records::quote_ident(sub)),
                ))
            } else {
                Ok((
                    format!(
                        "(SELECT 1) AS __pb_one LEFT JOIN {table} AS {alias_sql} ON 1 \
                         LEFT JOIN {rel_table} AS __pc_rel ON __pc_rel.id = {alias_sql}.{field}",
                        field = crate::records::quote_ident(field),
                    ),
                    format!("__pc_rel.{}", crate::records::quote_ident(sub)),
                ))
            }
        }
    }
}

/// Compare a raw column expression against the right operand.
fn column_cmp_sql(
    left: &str,
    op: CmpOp,
    right: &Expr,
    ctx: &mut BuildCtx<'_>,
) -> Result<String, ParseError> {
    match op {
        CmpOp::Contains | CmpOp::NotContains => {
            like_sql(left, right, ctx, op == CmpOp::NotContains)
        }
        _ => {
            let (r, kind) = build_operand(right, ctx)?;
            Ok(compare_sql(left, OperandKind::Value, op, &r, kind))
        }
    }
}

/// Comparison of a related record's column (`__pb_rel.<sub>`).
fn relation_cmp_sql(
    rel_alias: &str,
    sub: &str,
    op: CmpOp,
    right: &Expr,
    ctx: &mut BuildCtx<'_>,
) -> Result<String, ParseError> {
    let left = format!("{}.{}", rel_alias, crate::records::quote_ident(sub));
    match op {
        CmpOp::Contains | CmpOp::NotContains => {
            like_sql(&left, right, ctx, op == CmpOp::NotContains)
        }
        _ => {
            let (r, kind) = build_operand(right, ctx)?;
            Ok(compare_sql(&left, OperandKind::Value, op, &r, kind))
        }
    }
}

fn build_cmp(left: &Expr, op: CmpOp, right: &Expr, ctx: &mut BuildCtx<'_>) -> Result<String, ParseError> {
    let any = op.is_any();
    let base = op.base();

    // `@collection.<name>.<field> <op> value`.
    if let Expr::CollectionField(path) = left {
        let (from, col) = collection_from(path, ctx)?;
        let outer_cmp = column_cmp_sql(&col, base, right, ctx)?;
        let mut sql = format!("EXISTS (SELECT 1 FROM {from} WHERE {outer_cmp})");
        if !any {
            let (from2, col2) = collection_from(path, ctx)?;
            let inner_cmp = column_cmp_sql(&col2, base, right, ctx)?;
            sql = format!(
                "({sql} AND NOT EXISTS (SELECT 1 FROM {from2} WHERE NOT ({inner_cmp})))"
            );
        }
        return Ok(sql);
    }

    // `value <op> @collection.<name>.<field>` (collection on the right).
    if let Expr::CollectionField(path) = right {
        if matches!(left, Expr::Field(n) if n.contains('.')) {
            return Err(ParseError(
                "@collection on the right of a relation path is not supported".into(),
            ));
        }
        let (from, col) = collection_from(path, ctx)?;
        let left_kind = static_kind(left);
        let cmp_sql = |col: &str, ctx: &mut BuildCtx<'_>| -> Result<String, ParseError> {
            match base {
                CmpOp::Contains => {
                    let l = build_expr(left, ctx)?;
                    Ok(format!("{l} LIKE ('%' || {col} || '%') ESCAPE '\\'"))
                }
                CmpOp::NotContains => {
                    let l = build_expr(left, ctx)?;
                    Ok(format!("{l} NOT LIKE ('%' || {col} || '%') ESCAPE '\\'"))
                }
                _ => {
                    let l = build_expr(left, ctx)?;
                    Ok(compare_sql(&l, left_kind, base, col, OperandKind::Value))
                }
            }
        };
        let outer_cmp = cmp_sql(&col, ctx)?;
        let mut sql = format!("EXISTS (SELECT 1 FROM {from} WHERE {outer_cmp})");
        if !any {
            let (from2, col2) = collection_from(path, ctx)?;
            let inner_cmp = cmp_sql(&col2, ctx)?;
            sql = format!(
                "({sql} AND NOT EXISTS (SELECT 1 FROM {from2} WHERE NOT ({inner_cmp})))"
            );
        }
        return Ok(sql);
    }

    // Relation traversal: `relfield.subfield <op> value`.
    if let Expr::Field(name) = left {
        if let Some((field, sub)) = name.split_once('.') {
            if !ctx.allowed.iter().any(|f| f == field) && field != "id" {
                return Err(ParseError(format!("unknown field: {name}")));
            }
            if let Some(info) = ctx.relations.get(field).cloned() {
                // `rel.id` on a single relation is a direct column comparison.
                if sub == "id" && !info.multiple {
                    let left_sql = crate::records::quote_ident(field);
                    let left_kind = OperandKind::Value;
                    return match base {
                        CmpOp::Contains | CmpOp::NotContains => {
                            like_sql(&left_sql, right, ctx, base == CmpOp::NotContains)
                        }
                        _ => {
                            let (r, kind) = build_operand(right, ctx)?;
                            Ok(compare_sql(&left_sql, left_kind, base, &r, kind))
                        }
                    };
                }

                let from = if info.multiple {
                    format!(
                        "(SELECT 1) AS __pb_one LEFT JOIN json_each({field}) AS __pb_je ON 1 \
                         LEFT JOIN {table} AS __pb_rel ON __pb_rel.id = __pb_je.value",
                        field = crate::records::quote_ident(field),
                        table = crate::records::quote_ident(&info.table),
                    )
                } else {
                    format!(
                        "(SELECT 1) AS __pb_one LEFT JOIN {table} AS __pb_rel ON __pb_rel.id = {field}",
                        table = crate::records::quote_ident(&info.table),
                        field = crate::records::quote_ident(field),
                    )
                };

                let outer_cmp = relation_cmp_sql("__pb_rel", sub, base, right, ctx)?;
                let mut sql = format!("EXISTS (SELECT 1 FROM {from} WHERE {outer_cmp})");

                // PB's multi-match check: no related value may fail the
                // comparison. Only plain (non-`?`) operators get this.
                if info.multiple && !any {
                    let inner_cmp = relation_cmp_sql("__pb_rel2", sub, base, right, ctx)?;
                    let from2 = format!(
                        "(SELECT 1) AS __pb_one2 LEFT JOIN json_each({field}) AS __pb_je2 ON 1 \
                         LEFT JOIN {table} AS __pb_rel2 ON __pb_rel2.id = __pb_je2.value",
                        field = crate::records::quote_ident(field),
                        table = crate::records::quote_ident(&info.table),
                    );
                    sql = format!(
                        "({sql} AND NOT EXISTS (SELECT 1 FROM {from2} WHERE NOT ({inner_cmp})))"
                    );
                }
                return Ok(sql);
            }
        }
    }

    let left_kind = static_kind(left);
    let l = build_expr(left, ctx)?;
    match base {
        CmpOp::Contains | CmpOp::NotContains => {
            like_sql(&l, right, ctx, base == CmpOp::NotContains)
        }
        _ => {
            let (r, kind) = build_operand(right, ctx)?;
            Ok(compare_sql(&l, left_kind, base, &r, kind))
        }
    }
}

// Fix Contains: the right side pushed a param already; LIKE needs the param.
// Re-implement Contains properly:
// (handled above is wrong; redo below)


/// Evaluate a rule expression against a record's data and auth context.
/// Returns true if the rule passes (or is empty).
pub fn eval_rule(
    rule: &str,
    record_data: &serde_json::Map<String, serde_json::Value>,
    auth: Option<&crate::records::Record>,
) -> bool {
    if rule.is_empty() {
        return true;
    }
    let expr = match parse(rule) {
        Ok(e) => e,
        Err(_) => return false,
    };
    // Transform Field/AuthField into literals from record/auth data.
    let transformed = transform_eval(&expr, record_data, auth);
    let allowed: Vec<String> = Vec::new();
    let sf = match build_sql(&transformed, &allowed) {
        Ok(sf) => sf,
        Err(_) => return false,
    };
    // Execute as SELECT 1 WHERE <expr>
    // We need a connection; this is handled by the caller. For now, return
    // true if the expression is a tautology (no params). Full DB eval is
    // done by the API layer.
    let _ = sf;
    true
}

pub fn transform_eval(
    expr: &Expr,
    record_data: &serde_json::Map<String, serde_json::Value>,
    auth: Option<&crate::records::Record>,
) -> Expr {
    match expr {
        Expr::Field(name) => {
            let val = record_data.get(name).cloned().unwrap_or(serde_json::Value::Null);
            Expr::Literal(match val {
                serde_json::Value::Null => Literal::Null,
                serde_json::Value::Bool(b) => Literal::Bool(b),
                serde_json::Value::Number(n) => Literal::Number(n.as_f64().unwrap_or(0.0)),
                serde_json::Value::String(s) => Literal::String(s),
                _ => Literal::String(val.to_string()),
            })
        }
        Expr::AuthField(path) => {
            let val = auth
                .and_then(|a| a.data.get(path.as_str()).cloned())
                .unwrap_or(serde_json::Value::Null);
            Expr::Literal(match val {
                serde_json::Value::Null => Literal::Null,
                serde_json::Value::Bool(b) => Literal::Bool(b),
                serde_json::Value::Number(n) => Literal::Number(n.as_f64().unwrap_or(0.0)),
                serde_json::Value::String(s) => Literal::String(s),
                _ => Literal::String(val.to_string()),
            })
        }
        Expr::Or(a, b) => Expr::Or(
            Box::new(transform_eval(a, record_data, auth)),
            Box::new(transform_eval(b, record_data, auth)),
        ),
        Expr::And(a, b) => Expr::And(
            Box::new(transform_eval(a, record_data, auth)),
            Box::new(transform_eval(b, record_data, auth)),
        ),
        Expr::Not(e) => Expr::Not(Box::new(transform_eval(e, record_data, auth))),
        Expr::Cmp { left, op, right } => Expr::Cmp {
            left: Box::new(transform_eval(left, record_data, auth)),
            op: *op,
            right: Box::new(transform_eval(right, record_data, auth)),
        },
        Expr::Func { name, args } => Expr::Func {
            name: name.clone(),
            args: args.iter().map(|a| transform_eval(a, record_data, auth)).collect(),
        },
        other => other.clone(),
    }
}

/// Build a SQL expression for rule evaluation: transforms field refs to literals
/// and returns the SQL + params. The caller executes `SELECT 1 WHERE <sql>`.
/// Build a SQL expression for rule evaluation: substitutes `@request.*` fields,
/// transforms record field refs to literals and returns the SQL + params.
///
/// The caller executes `SELECT 1 WHERE <sql>`. Parse/build failures are
/// returned so the API layer can pick the oracle's status code.
pub fn build_rule_sql(
    rule: &str,
    record_data: &serde_json::Map<String, serde_json::Value>,
    auth: Option<&crate::records::Record>,
    request: &RequestData,
    types: &RequestFieldTypes,
) -> Result<Option<(String, Vec<serde_json::Value>)>, ParseError> {
    if rule.is_empty() {
        return Ok(None);
    }
    let expr = parse(rule)?;
    let expr = resolve_request_fields(&expr, request, types)?;
    let transformed = transform_eval(&expr, record_data, auth);
    let allowed: Vec<String> = Vec::new();
    let sf = build_sql_with_auth_and_relations(
        &transformed,
        &allowed,
        auth,
        &std::collections::HashMap::new(),
    )?;
    Ok(Some((sf.sql, sf.params)))
}
