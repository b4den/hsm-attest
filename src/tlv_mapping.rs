use paste::paste;
use std::{fmt::Formatter, ops::Deref};
use std::fmt::Write;

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
                    $(Self::$attr_name => crate::tlv_mapping::$typ::encode(bytes, len)
                        .map(|x| crate::tlv_mapping::TLVValue::$typ(x)),)*
                    //Self::UNKNOWN => Some(crate::tlv_mapping::TLVValue::Bytes(Bytes(bytes.to_vec()))),
                    Self::UNKNOWN => Bytes::encode(bytes, len).map(crate::tlv_mapping::TLVValue::Bytes),
                }.unwrap_or_else(|| TLVValue::RawBytes(RawBytes(bytes.to_vec())))
            }
        }


        paste! {
            impl std::fmt::Display for $name {
                fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
                    match *self {
                        $( Self::$attr_name => {
                            write!(f, "{} (ID: {})", stringify!( [< $attr_name:camel >]), $id)
                        }),*,
                        Self::UNKNOWN => write!(f, "{} ", "Unknown"),
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

pub trait EncodeTLV: std::ops::Deref {
    fn encode(bytes: &[u8], len: u32) -> Option<Self>
    where
        Self: Sized;
    fn to_str(&self) -> String;
}

#[derive(Debug)]
pub struct ClassKey(u32);
impl EncodeTLV for ClassKey {
    fn encode(bytes: &[u8], len: u32) -> Option<Self>
    where
        Self: Sized,
    {
        None
    }

    fn to_str(&self) -> String {
        format!("{}", self.0)
    }
}

impl Deref for ClassKey {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct Bool(bool);
impl EncodeTLV for Bool {
    fn encode(bytes: &[u8], _len: u32) -> Option<Self>
    where
        Self: Sized,
    {
        bytes.get(0).map(|b| *b > 0).map(|b| Bool(b))
    }

    fn to_str(&self) -> String {
        format!("{}", self.0)
    }
}
impl Deref for Bool {
    type Target = bool;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct HexStr128(String);
impl EncodeTLV for HexStr128 {
    fn encode(bytes: &[u8], _len: u32) -> Option<Self>
    where
        Self: Sized,
    {
        String::from_utf8(bytes.to_vec())
            .ok()
            .map(HexStr128)
    }

    fn to_str(&self) -> String {
        format!("{}", self.0)
    }
}

impl Deref for HexStr128 {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct Bytes(String);
impl EncodeTLV for Bytes {
    fn encode(bytes: &[u8], len: u32) -> Option<Self>
    where
        Self: Sized,
    {
        let mut s = String::with_capacity(len as _);
        for byte in bytes {
            write!(&mut s, "{:02x}", byte).ok()?;
        }
        //Some(HexStr128(s))
        Some(Bytes(s))
    }

    fn to_str(&self) -> String {
        format!("{}", self.0)
    }
}

impl Deref for Bytes {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct ByteStr(String);
impl EncodeTLV for ByteStr {
    fn encode(bytes: &[u8], len: u32) -> Option<Self>
    where
        Self: Sized,
    {
        let mut s = Vec::with_capacity(len as _);
        for byte in bytes {
            if *byte == 0x00 {
                break;
            } else {
                s.push(*byte);
            }
        }
        String::from_utf8(s).ok()
                 .map(ByteStr)
    }

    fn to_str(&self) -> String {
        format!("{}", self.0)
    }
}

impl Deref for ByteStr {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct RawBytes(Vec<u8>);
impl EncodeTLV for RawBytes {
    fn encode(bytes: &[u8], _len: u32) -> Option<Self>
    where
        Self: Sized,
    {
        Some(RawBytes(bytes.to_vec()))
    }

    fn to_str(&self) -> String {
        format!("{:?}", self.0)
    }
}

impl Deref for RawBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct Int(u32);
impl EncodeTLV for Int {
    //fn encode(bytes: &[u8], len: u32) -> Option<Self>
    //where
    //    Self: Sized,
    //{
    //    let index_mask = (len as i32 ^ 3) - 1 >> 31;
    //    let start_index = (index_mask & 1) | (!index_mask & 0);
    //    let val = if start_index == 1 {
    //        u32::from_be_bytes([0x00, bytes[0], bytes[1], bytes[2]])
    //    } else {
    //        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    //    };
    //    Some(Int(val))
    //}
    fn encode(bytes: &[u8], _len: u32) -> Option<Self>
    where
        Self: Sized,
    {
        let mut val = 0;
        for v in bytes {
            val = val << 8 | *v as u32;
        }

        Some(Int(val))
    }

    fn to_str(&self) -> String {
        format!("{}", self.0)
    }
}

impl Deref for Int {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub enum TLVValue {
    Bool(Bool),
    ClassKey(ClassKey),
    HexStr128(HexStr128),
    Bytes(Bytes),
    RawBytes(RawBytes),
    ByteStr(ByteStr),
    Int(Int),
}

impl TLVValue {
    pub fn to_str(&self) -> String {
        match self {
            TLVValue::Bool(ref b) => b.to_str(),
            TLVValue::ClassKey(b) => b.to_str(),
            TLVValue::HexStr128(b) => b.to_str(),
            TLVValue::Bytes(b) => b.to_str(),
            TLVValue::RawBytes(b) => b.to_str(),
            TLVValue::ByteStr(b) => b.to_str(),
            TLVValue::Int(b) => b.to_str(),
        }
    }
}


tlv_mapping! {
    pub enum TLVMapping {
        //// 2 => public key in a public-private key pair
        //// 3 => private key in a public-private key pair
        //// 4 => Secret (symmetric) key
        // Class type of the key.
        0x0000 => OBJ_ATTR_CLASS = ClassKey,
        // Identifies the key as a token key.
        0x0001 => OBJ_ATTR_TOKEN = Bytes,
        // Indicates if this is a shared key or a private key (for symmetric or asymmetric keys).
        0x0002 => OBJ_ATTR_PRIVATE = Bool,
        // Key description.
        0x0003 => OBJ_ATTR_LABEL = ByteStr,
        // The key can be trusted for the application that it was created.
        0x0086 => OBJ_ATTR_TRUSTED = Bool,
        // Subclass type of the key.
        0x0100 => OBJ_ATTR_KEY_TYPE = Bytes,
        // Key identifier.
        0x0102 => OBJ_ATTR_ID = HexStr128,
        // Always true for keys generated on HSM.
        0x0103 => OBJ_ATTR_SENSITIVE = Bool,
        // Indicates if key can be used to encrypt data for operations like RSA_Encrypt. Not applicable to EC keys.
        0x0104 => OBJ_ATTR_ENCRYPT = Bool,
        // Indicates if key can be used to decrypt data for operations like RSA_Decrypt. Not applicable to EC keys.
        0x0105 => OBJ_ATTR_DECRYPT = Bool,
        // Indicates if key can be used to wrap other keys.
        0x0106 => OBJ_ATTR_WRAP	= Bool,
        // Indicates if key can be used to unwrap other keys.
        0x0107 => OBJ_ATTR_UNWRAP = Bool,
        // Indicates if key can be used for signing operations.
        0x0108 => OBJ_ATTR_SIGN	= Bool,
        // Indicates if key can be used for verifying operations.
        0x010A => OBJ_ATTR_VERIFY = Bool,
        // Indicates if key supports key derivation (i.e. if other keys can be derived from this one).
        0x010C => OBJ_ATTR_DERIVE = Bool,
        // RSA key modulus value.
        0x0120 => OBJ_ATTR_MODULUS = Bytes,
        // RSA key size in bits.
        0x0121 => OBJ_ATTR_MODULUS_BITS	= Int,
        // RSA key public exponent value.
        0x0122 => OBJ_ATTR_PUBLIC_EXPONENT = Int,
        // Length in bytes of any value.
        0x0161 => OBJ_ATTR_VALUE_LEN = Int,
        // Indicates if key can be extracted.
        0x0162 => OBJ_ATTR_EXTRACTABLE = Bool,
        // Indicates if key was generated locally
        0x0163 => OBJ_ATTR_LOCAL = Bool,
        // Indicates if key can never be extracted.
        0x0164 => OBJ_ATTR_NEVER_EXTRACTABLE = Bool,
        // Indicates if key has always had the OBJ_ATTR_SENSITIVE attribute set.
        0x0165 => OBJ_ATTR_ALWAYS_SENSITIVE = Bool,
        // Key Check Value.
        0x0173 => OBJ_ATTR_KCV	= Bytes,
        // Extended Attribute #1
        0x1000 => OBJ_EXT_ATTR1	= Bytes,
        // Extended Key Check Value.
        0x1003 => OBJ_ATTR_EKCV	= Bytes,
        // Indicates if key can only be wrapped with a wrapping key that has OBJ_ATTR_TRUSTED set.
        0x0210 => OBJ_ATTR_WRAP_WITH_TRUSTED = Bool,
        // Indicates if key can be split into multiple parts.
        0x80000002 => OBJ_ATTR_SPLITTABLE = Bool,
        // Indicate if it is part of the key split.
        0x80000003 => OBJ_ATTR_IS_SPLIT	= Bool,
        // Indicate if key supports encryption.
        0x80000174 => OBJ_ATTR_ENCRYPT_KEY_MECHANISMS = Bool,
        // Indicate if key supports decryption.
        0x80000175 => OBJ_ATTR_DECRYPT_KEY_MECHANISMS = Bool,
        // Indicate if key supports signing.
        0x80000176 => OBJ_ATTR_SIGN_KEY_MECHANISMS = Bool,
        // Indicate if key supports signature verification.
        0x80000177 => OBJ_ATTR_VERIFY_KEY_MECHANISMS = Bool,
        // Indicate if key supports key wrapping.
        0x80000178 => OBJ_ATTR_WRAP_KEY_MECHANISMS = Bool,
        // Indicate if key supports key unwrapping.
        0x80000179 => OBJ_ATTR_UNWAP_KEY_MECHANISMS = Bool,
        // Indicate if key supports key derivation.
        0x80000180 => OBJ_ATTR_DERIVE_KEY_MECHANISMS = Bool,

        // Unknown at this stage
        0x80000000 => OBJ_UNKNOWN = Bytes,
    }
}
