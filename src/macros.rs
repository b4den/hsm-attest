macro_rules! enum_builder {
    ($(#[$comment:meta])* $enum_vis:vis enum $enum_name:ident { $( $(#[$met:meta])? $name:ident $(= $exp:expr)?, )*}  ) => {

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
