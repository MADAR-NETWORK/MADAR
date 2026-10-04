//! Reads SCALE bytes into a plain value tree using the chain's own type registry (runtime metadata).
//! Bounded: depth and lengths are limited so hostile input cannot exhaust memory or stack.

use frame_metadata::{RuntimeMetadata, RuntimeMetadataPrefixed};
use parity_scale_codec::{Compact, Decode};
use scale_info::{form::PortableForm, PortableRegistry, TypeDef, TypeDefPrimitive};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "t", content = "v", rename_all = "lowercase")]
pub enum Value {
    Bool(bool),
    /// Unsigned / signed integers as decimal strings (no precision loss in JSON).
    Num(String),
    Text(String),
    Bytes(String),
    Account(String),
    Seq(Vec<Value>),
    Fields(Vec<(String, Value)>),
    Variant(String, Vec<(String, Value)>),
    Call(Box<Call>),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Call {
    pub pallet: String,
    pub call: String,
    pub args: Vec<(String, Value)>,
}

pub struct Meta {
    pub types: PortableRegistry,
    /// (pallet index, pallet name, calls enum type id)
    pub pallets: Vec<(u8, String, Option<u32>)>,
}

impl Meta {
    pub fn from_bytes(mut b: &[u8]) -> Result<Meta, String> {
        let m = RuntimeMetadataPrefixed::decode(&mut b).map_err(|e| format!("metadata: {e}"))?;
        macro_rules! take {
            ($v:expr) => {
                Meta {
                    pallets: $v
                        .pallets
                        .iter()
                        .map(|p| (p.index, p.name.clone(), p.calls.as_ref().map(|c| c.ty.id)))
                        .collect(),
                    types: $v.types,
                }
            };
        }
        Ok(match m.1 {
            RuntimeMetadata::V14(v) => take!(v),
            RuntimeMetadata::V15(v) => take!(v),
            RuntimeMetadata::V16(v) => take!(v),
            _ => return Err("metadata: unsupported version (need v14+)".into()),
        })
    }
}

const MAX_DEPTH: u32 = 48;

pub struct Decoder<'a> {
    meta: &'a Meta,
    prefix: u16,
}

type R<T> = Result<T, String>;

impl<'a> Decoder<'a> {
    pub fn new(meta: &'a Meta, prefix: u16) -> Self {
        Decoder { meta, prefix }
    }

    /// A runtime call: pallet index byte, then that pallet's call enum.
    pub fn call(&self, b: &mut &[u8], depth: u32) -> R<Call> {
        if depth > MAX_DEPTH {
            return Err("nested too deep".into());
        }
        let idx = take(b, 1)?[0];
        let (_, name, ty) = self
            .meta
            .pallets
            .iter()
            .find(|p| p.0 == idx)
            .ok_or_else(|| format!("unknown pallet index {idx}"))?;
        let ty = ty.ok_or_else(|| format!("pallet {name} has no calls"))?;
        match self.value(ty, b, depth + 1)? {
            Value::Variant(call, args) => Ok(Call {
                pallet: name.clone(),
                call,
                args,
            }),
            _ => Err("call is not an enum".into()),
        }
    }

    pub fn value(&self, id: u32, b: &mut &[u8], depth: u32) -> R<Value> {
        if depth > MAX_DEPTH {
            return Err("nested too deep".into());
        }
        let ty = self
            .meta
            .types
            .resolve(id)
            .ok_or_else(|| format!("unknown type {id}"))?;
        let last = ty.path.segments.last().map(String::as_str).unwrap_or("");
        match &ty.type_def {
            TypeDef::Variant(v) if last == "RuntimeCall" => {
                let _ = v;
                Ok(Value::Call(Box::new(self.call(b, depth + 1)?)))
            }
            TypeDef::Composite(c) => {
                if last == "AccountId32" && c.fields.len() == 1 {
                    let raw: [u8; 32] = take(b, 32)?.try_into().unwrap();
                    return Ok(Value::Account(crate::ss58::encode(&raw, self.prefix)));
                }
                let fields = self.fields(&c.fields, b, depth)?;
                // unwrap single unnamed wrappers (Perbill(u32), H256([u8;32]) …) to keep output readable
                if fields.len() == 1 && fields[0].0.is_empty() {
                    return Ok(fields.into_iter().next().unwrap().1);
                }
                Ok(Value::Fields(fields))
            }
            TypeDef::Variant(v) => {
                let i = take(b, 1)?[0];
                let var = v
                    .variants
                    .iter()
                    .find(|x| x.index == i)
                    .ok_or_else(|| format!("bad variant {i} for {last}"))?;
                Ok(Value::Variant(
                    var.name.clone(),
                    self.fields(&var.fields, b, depth)?,
                ))
            }
            TypeDef::Sequence(s) => {
                let n = Compact::<u32>::decode(b).map_err(|_| "bad length")?.0 as usize;
                self.many(s.type_param.id, n, b, depth)
            }
            TypeDef::Array(a) => self.many(a.type_param.id, a.len as usize, b, depth),
            TypeDef::Tuple(t) => {
                if t.fields.is_empty() {
                    return Ok(Value::Fields(vec![]));
                }
                let mut out = Vec::with_capacity(t.fields.len());
                for f in &t.fields {
                    out.push(self.value(f.id, b, depth + 1)?);
                }
                Ok(Value::Seq(out))
            }
            TypeDef::Primitive(p) => prim(p, b),
            TypeDef::Compact(_) => {
                let n = Compact::<u128>::decode(b).map_err(|_| "bad compact")?.0;
                Ok(Value::Num(n.to_string()))
            }
            TypeDef::BitSequence(bs) => {
                let bits = Compact::<u32>::decode(b).map_err(|_| "bad bit length")?.0 as usize;
                let store = match self
                    .meta
                    .types
                    .resolve(bs.bit_store_type.id)
                    .map(|t| &t.type_def)
                {
                    Some(TypeDef::Primitive(TypeDefPrimitive::U16)) => 2,
                    Some(TypeDef::Primitive(TypeDefPrimitive::U32)) => 4,
                    Some(TypeDef::Primitive(TypeDefPrimitive::U64)) => 8,
                    _ => 1,
                };
                let words = bits.div_ceil(store * 8);
                let raw = take(b, words * store)?;
                Ok(Value::Bytes(format!("0x{}", hex::encode(raw))))
            }
        }
    }

    fn fields(
        &self,
        fs: &[scale_info::Field<PortableForm>],
        b: &mut &[u8],
        depth: u32,
    ) -> R<Vec<(String, Value)>> {
        let mut out = Vec::with_capacity(fs.len());
        for f in fs {
            out.push((
                f.name.clone().unwrap_or_default(),
                self.value(f.ty.id, b, depth + 1)?,
            ));
        }
        Ok(out)
    }

    fn many(&self, elem: u32, n: usize, b: &mut &[u8], depth: u32) -> R<Value> {
        let is_u8 = matches!(
            self.meta.types.resolve(elem).map(|t| &t.type_def),
            Some(TypeDef::Primitive(TypeDefPrimitive::U8))
        );
        if is_u8 {
            let raw = take(b, n)?;
            return Ok(match std::str::from_utf8(raw) {
                Ok(s) if !s.is_empty() && s.chars().all(|c| !c.is_control() || c == '\n') => {
                    Value::Text(s.to_string())
                }
                _ => Value::Bytes(format!("0x{}", hex::encode(raw))),
            });
        }
        // every element takes at least one byte (except unit types): reject impossible lengths early
        if n > b.len() && n > 0 {
            let zero_sized = matches!(self.meta.types.resolve(elem).map(|t| &t.type_def), Some(TypeDef::Tuple(t)) if t.fields.is_empty());
            if !zero_sized || n > 10_000 {
                return Err("length longer than the data".into());
            }
        }
        let mut out = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            out.push(self.value(elem, b, depth + 1)?);
        }
        Ok(Value::Seq(out))
    }
}

fn take<'b>(b: &mut &'b [u8], n: usize) -> R<&'b [u8]> {
    if b.len() < n {
        return Err("unexpected end of data".into());
    }
    let (h, t) = b.split_at(n);
    *b = t;
    Ok(h)
}

fn prim(p: &TypeDefPrimitive, b: &mut &[u8]) -> R<Value> {
    use TypeDefPrimitive::*;
    let le = |raw: &[u8]| {
        let mut x = [0u8; 16];
        x[..raw.len()].copy_from_slice(raw);
        u128::from_le_bytes(x)
    };
    let sle = |raw: &[u8]| {
        let neg = raw.last().map(|x| x & 0x80 != 0).unwrap_or(false);
        let mut x = [if neg { 0xff } else { 0 }; 16];
        x[..raw.len()].copy_from_slice(raw);
        i128::from_le_bytes(x)
    };
    Ok(match p {
        Bool => Value::Bool(match take(b, 1)?[0] {
            0 => false,
            1 => true,
            _ => return Err("bad bool".into()),
        }),
        Char => Value::Text(
            char::from_u32(le(take(b, 4)?) as u32)
                .map(String::from)
                .unwrap_or_default(),
        ),
        Str => {
            let n = Compact::<u32>::decode(b).map_err(|_| "bad length")?.0 as usize;
            Value::Text(String::from_utf8_lossy(take(b, n)?).into_owned())
        }
        U8 => Value::Num(le(take(b, 1)?).to_string()),
        U16 => Value::Num(le(take(b, 2)?).to_string()),
        U32 => Value::Num(le(take(b, 4)?).to_string()),
        U64 => Value::Num(le(take(b, 8)?).to_string()),
        U128 => Value::Num(le(take(b, 16)?).to_string()),
        I8 => Value::Num(sle(take(b, 1)?).to_string()),
        I16 => Value::Num(sle(take(b, 2)?).to_string()),
        I32 => Value::Num(sle(take(b, 4)?).to_string()),
        I64 => Value::Num(sle(take(b, 8)?).to_string()),
        I128 => Value::Num(sle(take(b, 16)?).to_string()),
        U256 | I256 => Value::Bytes(format!("0x{}", hex::encode(take(b, 32)?))),
    })
}

impl Value {
    pub fn field<'v>(args: &'v [(String, Value)], name: &str) -> Option<&'v Value> {
        args.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// The first account found inside this value (e.g. MultiAddress::Id(account)).
    pub fn account(&self) -> Option<&str> {
        match self {
            Value::Account(a) => Some(a),
            Value::Variant(_, f) | Value::Fields(f) => f.iter().find_map(|(_, v)| v.account()),
            Value::Seq(s) => s.iter().find_map(|v| v.account()),
            _ => None,
        }
    }

    pub fn accounts<'v>(&'v self, out: &mut Vec<&'v str>) {
        match self {
            Value::Account(a) => out.push(a),
            Value::Variant(_, f) | Value::Fields(f) => f.iter().for_each(|(_, v)| v.accounts(out)),
            Value::Seq(s) => s.iter().for_each(|v| v.accounts(out)),
            Value::Call(c) => c.args.iter().for_each(|(_, v)| v.accounts(out)),
            _ => {}
        }
    }

    pub fn num(&self) -> Option<u128> {
        match self {
            Value::Num(n) => n.parse().ok(),
            Value::Fields(f) if f.len() == 1 => f[0].1.num(),
            _ => None,
        }
    }

    pub fn variant_name(&self) -> Option<&str> {
        match self {
            Value::Variant(n, _) => Some(n),
            _ => None,
        }
    }
}
