use curl::easy::Easy;

fn getip()->String{
    let mut easy = Easy::new();
    easy.url("https://am.i.mullvad.net/ip").unwrap();
    let mut transfer = easy.transfer();
    transfer.write_function(|data|{
        ip = data;
        Ok(data.len())
    }).unwrap();
    transfer.perform().unwrap();
    ip
}






#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
