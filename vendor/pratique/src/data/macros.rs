/// Explicit field order and optional omission predicates for a record.
#[macro_export]
macro_rules! data_encode {
 ($ty:ty {$($field:ident $(=> $skip:expr)?),* $(,)?})=>{
 impl $crate::data::Encode for $ty {
 fn encode(&self)->Result<$crate::data::Node,$crate::data::Error>{
  let Self{$($field:_),*}=self; // Adding a field requires an explicit wire decision.
  let mut fields=Vec::new();
  $($crate::data_encode!(@field fields,self,$field $(,$skip)?);)*
  Ok($crate::data::Node::new($crate::data::Kind::Object(fields)))
 }} };
 (@field $out:ident,$this:ident,$f:ident)=>{$out.push((stringify!($f).trim_start_matches("r#").to_owned(),$crate::data::Encode::encode(&$this.$f)?));};
 (@field $out:ident,$this:ident,$f:ident,$skip:expr)=>{if !($skip)(&$this.$f){$out.push((stringify!($f).trim_start_matches("r#").to_owned(),$crate::data::Encode::encode(&$this.$f)?));}};
}
/// Decode a named record with explicit defaults and unknown-field policy.
#[macro_export]
macro_rules! data_decode {
 ($ty:ty, deny_unknown=$deny:expr, {$($field:ident $(= $default:expr)?),* $(,)?})=>{
 impl $crate::data::Decode for $ty {
 fn decode(node:$crate::data::Node)->Result<Self,$crate::data::Error>{
  let mut fields=$crate::data::Fields::new(node,$deny)?;
  let value=Self{$($field:$crate::data_decode!(@field fields,$field $(,$default)?)),*};
  fields.finish()?;Ok(value)
 }} };
 (@field $fields:ident,$f:ident)=>{$fields.field(stringify!($f).trim_start_matches("r#"))?};
 (@field $fields:ident,$f:ident,$default:expr)=>{$fields.field_or(stringify!($f).trim_start_matches("r#"),||$default)?};
}
