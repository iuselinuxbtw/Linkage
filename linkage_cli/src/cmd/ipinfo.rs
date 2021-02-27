//! Contains the `ipinfo` subcommand.

use crate::error::CliResult;
use clap::ArgMatches;
use linkage_leaks::{dns_test, get_ip_information, IpInformation};

pub fn cmd_ipinfo(matches: &ArgMatches) -> CliResult<()> {
    // Output ip information if wanted
    if !matches.is_present("no-ip") {
        let (info4, info6) = get_ip_information()?;

        // IPv4 should be printed
        if !matches.is_present("no-ip4") {
            println!();
            println!("----- IPv4 -----");
            print_ip_information(info4);
        }

        // IPv6 should be printed
        if !matches.is_present("no-ip6") {
            println!();
            println!("----- IPv6 -----");
            print_ip_information(info6);
        }
    }

    // Do dns test if wanted
    if !matches.is_present("no-dns") {
        let dns_servers = dns_test(matches.value_of("dns_requests").unwrap().parse()?)?;

        println!();
        println!("----- DNS servers -----");
        if dns_servers.len() > 0 {
            for d in dns_servers {
                println!("- {}", d);
            }
        } else {
            println!("No DNS servers found");
        }
    }

    Ok(())
}

/// Print out the supplied ip information.
fn print_ip_information(i: IpInformation) {
    println!("IP: {}", i.ip);
    println!("Country: {} ({})", i.country_name, i.country_code);
    println!("Region: {} ({})", i.region_name, i.region_code);
    println!("Continent: {} ({})", i.continent_name, i.continent_code);
    println!(
        "City: {} ({}) ({})",
        i.city_name,
        i.postal_code.unwrap_or_else(|| String::from("-")),
        i.postal_confidence.unwrap_or_else(|| String::from("-"))
    );
    println!(
        "Metro code: {}",
        i.metro_code.unwrap_or_else(|| String::from("-"))
    );
    println!(
        "Lat/Long: {}/{} (Accuracy: {}km)",
        i.latitude, i.longitude, i.accuracy_radius
    );
}
