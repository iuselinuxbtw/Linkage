/// Expects an execute for the supplied identifier 1 time. Returns `Ok(())` by default but that can
/// be customized using another parameter.
#[macro_export]
macro_rules! expect_execute {
    ( $m:ident, $e:expr ) => {
        expect_execute!($m, $e, Ok(()));
    };
    ( $m:ident, $e:expr, $returns:expr ) => {
        {
            $m.expect_execute()
                .times(1)
                .with(eq($e))
                .returning(|_| $returns);
        }
    };
}