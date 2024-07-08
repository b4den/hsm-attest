use std::fmt::Formatter;
use paste::paste;

macro_rules! tlv_mapping {
    ($(#[$comment:meta])* $enum_vis:vis enum $name:ident { $( $($attr_comments:meta)?  $id:expr => $attr_name:ident = $typ:ident,)*} ) => {
            $($comment)?
            #[allow(non_camel_case_types)]
            #[derive(Debug, Copy, Clone)]
            $enum_vis enum $name {
                $($attr_name),*
                ,UNKNOWN
            }


        impl $name {
            pub fn from_int(val: u32) -> Self {
                match val {
                    $( $id => Self::$attr_name),*,
                    _ => Self::UNKNOWN,
                }
            }

            // should give us an enum of bytes, u32, bool
            pub fn encode(&self, bytes: &[u8], len: u32) -> TLVValue {
                match *self {
                    $(Self::$attr_name => TLVValue::from(crate::tlv_mapping::TLVValue::$typ(crate::tlv_mapping::$typ::encode(bytes, len).unwrap())),)*
                    Self::UNKNOWN => crate::tlv_mapping::TLVValue::Bytes(Bytes(bytes.to_vec())),
                    //Self::UNKNOWN => Some(Bytes::encode(bytes, len)),
                }
            }
        }


        paste! {
            impl std::fmt::Display for $name {
                fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
                    match *self {
                        $( Self::$attr_name => {
                            write!(f, "{} (ID: {})", stringify!( [< $attr_name:camel >]), $id)
                        }),*,
                        Self::UNKNOWN => write!(f, "{} (ID: {})", "Unknown", stringify!($($id)*)),
                    }
                }
            }
        }
    };
}

// #[repr(u8)]
// pub enum ClassKey {
//     Pubkey = 2,
//     Privkey = 3,
//     // symmetric key
//     Secret = 4,
// }

pub trait EncodeTLV {
    fn encode(bytes: &[u8], len: u32) -> Option<Self> where Self: Sized;
    fn into_tlv(self) -> TLVValue;
}

#[derive(Debug)]
pub struct ClassKey(u32);
impl EncodeTLV for ClassKey {
    fn encode(bytes: &[u8], len: u32) -> Option<Self> where Self: Sized {
        None
    }
    fn into_tlv(self) -> TLVValue {
        TLVValue::ClassKey(self)
    }
}

#[derive(Debug)]
pub struct Bool(bool);
impl EncodeTLV for Bool {
    fn encode(bytes: &[u8], len: u32) -> Option<Self> where Self: Sized {
        None
    }

    fn into_tlv(self) -> TLVValue {
        TLVValue::Bool(self)
    }
}

#[derive(Debug)]
pub struct HexStr128(String);
impl EncodeTLV for HexStr128 {
    fn encode(bytes: &[u8], len: u32) -> Option<Self> where Self: Sized {
       None
    }
    fn into_tlv(self) -> TLVValue {
        TLVValue::HexStr128(self)
    }
}

#[derive(Debug)]
pub struct Bytes(Vec<u8>);
impl EncodeTLV for Bytes {
    fn encode(bytes: &[u8], len: u32) -> Option<Self> where Self: Sized {
        None
    }
    fn into_tlv(self) -> TLVValue {
        TLVValue::Bytes(self)
    }
}

#[derive(Debug)]
pub struct Int(u32);
impl EncodeTLV for Int {
    fn encode(bytes: &[u8], len: u32) -> Option<Self> where Self: Sized {
        None
    }
    fn into_tlv(self) -> TLVValue {
        TLVValue::Int(self)
    }
}

#[derive(Debug)]
pub enum TLVValue {
    Bool(Bool),
    ClassKey(ClassKey),
    HexStr128(HexStr128),
    Bytes(Bytes),
    Int(Int),
}


tlv_mapping! {
    pub enum TLVMapping {
        // 2 => public key in a public-private key pair
        // 3 => private key in a public-private key pair
        // 4 => Secret (symmetric) key
        0x0000 => OBJ_ATTR_CLASS = ClassKey,
        0x0001 => OBJ_ATTR_TOKEN = Bytes,
        0x0103 => OBJ_ATTR_SENSITIVE = Bool,
        // key identifier
        0x0102 => OBJ_ATTR_ID = HexStr128,
    }
}
