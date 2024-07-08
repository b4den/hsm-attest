use std::fmt::Formatter;

macro_rules! tlv_mapping {
    ($(#[$comment:meta])* $enum_vis:vis enum $name:ident { $( $($attr_comments:meta)?  $id:expr => $attr_name:ident = $typ:ty,)*} ) => {
        $($comment)?
        #[allow(non_camel_case_types)]
        #[derive(Debug, Copy, Clone)]
        $enum_vis enum $name {
            $($attr_name),*
        }

        impl $name {
            pub fn from_int(val: u32) -> Option<Self> {
                match val {
                    $( $id => Some(Self::$attr_name) ),*,
                    _ => None
                }
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
                match *self {
                    $( Self::$attr_name => {
                        write!(f, "{} (ID: {})", stringify!($attr_name), $id)
                    }),*,
                }
            }
        }
    };
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
