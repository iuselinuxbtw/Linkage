//! Utilities related to the firewall backends and their implementation.

/// Turns the supplied arguments into a Vec<String>. Converts the arguments using String::from.
#[macro_export]
macro_rules! to_string_vec {
    ( $( $x:expr ),* ) => {
        {
            vec![
                $(
                    String::from($x),
                )*
            ]
        }
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_to_string_vec() {
        let v1: Vec<String> = vec![];
        let v2: Vec<String> = to_string_vec!();
        assert_eq!(
            v1,
            v2,
        );
        assert_eq!(
            vec![String::from("Hello"), String::from("World")],
            to_string_vec!("Hello", "World"),
        );
        assert_eq!(
            vec![String::from("Hello"), String::from("World"), String::from("!!!")],
            to_string_vec!("Hello", "World", "!!!"),
        );
    }
}