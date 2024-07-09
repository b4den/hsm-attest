macro_rules! enum_builder {
    ($(#[$comment:meta])* $enum_vis:vis enum $enum_name:ident { $( $(#[$met:meta])? $name:ident $(= $exp:expr)?, )*}  ) => {

        $($comment)*
        #[derive(Default, Copy, Clone, Debug, PartialEq, FromPrimitive)]
        #[repr(u8)]
        $enum_vis enum $enum_name {
            $( $name ),*
            ,#[default]
            Unknown
        }

        impl $enum_name {
            const fn attr_count() -> usize {
                [$($enum_name::$name),*, $enum_name::Unknown].len()
            }
        }
    };
}

macro_rules! tlv_mapping {
    ($(#[$comment:meta])* $enum_vis:vis enum $name:ident { $( $($attr_comments:meta)?  $id:expr => $attr_name:ident = $typ:ident,)*} ) => {
            $($comment)*
            #[allow(non_camel_case_types)]
            #[derive(Copy, Clone)]
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

            pub fn encode(&self, bytes: &[u8], len: u32) -> TLVValue {
                match *self {
                    $(Self::$attr_name => crate::tlv_mapping::$typ::encode(bytes, len)
                        .map(crate::tlv_mapping::TLVValue::$typ),)*
                    Self::UNKNOWN => Bytes::encode(bytes, len)
                        .map(crate::tlv_mapping::TLVValue::Bytes),
                }.unwrap_or_else(|| TLVValue::RawBytes(RawBytes(bytes.to_vec())))
            }
        }


        paste! {
            impl std::fmt::Display for $name {
                fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
                    match *self {
                        $( Self::$attr_name => {
                            write!(f, "{}", stringify!( [< $attr_name:camel >]))
                        }),*,
                        Self::UNKNOWN => write!(f, "{} ", "Unknown"),
                    }
                }
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
                match *self {
                    $( Self::$attr_name => {
                        write!(f, "{} (ID: {})", stringify!( [< $attr_name:camel >]), $id)
                    }),*,
                    Self::UNKNOWN => write!(f, "{} ", "Unknown"),
                }
            }
        }
    };
}
