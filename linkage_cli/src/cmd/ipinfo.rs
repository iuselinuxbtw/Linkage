//! Contains the `ipinfo` subcommand.

use clap::{ArgMatches, App as ClapApp, Arg as ClapArg};
use crate::error::CliResult;
use linkage_leaks::{IpInformation, get_ip_information, dns_test};
use crate::cmd::Command;

pub struct CommandIpInfo;

impl Command for CommandIpInfo {
    fn run(&self, matches: &ArgMatches) -> CliResult<()> {
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
            // TODO: Make amount of requests configurable
            let dns_servers = dns_test(100)?;

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

    fn get_subcommand(&self) -> &str {
        "ipinfo"
    }

    fn get_clap_app(&self) -> ClapApp {
        ClapApp::new("ipinfo")
            .about("outputs ip information and does dns tests")
            .arg(ClapArg::with_name("no-ip")
                .help("Do not check ip address")
                .long("no-ip")
                .takes_value(false))
            .arg(ClapArg::with_name("no-ip4")
                .help("Do not output ipv4 address information")
                .long("no-ip4")
                .takes_value(false))
            .arg(ClapArg::with_name("no-ip6")
                .help("Do not output ipv6 address information")
                .long("no-ip6")
                .takes_value(false))
            .arg(ClapArg::with_name("no-dns")
                .help("Do not run dns tests")
                .long("no-dns")
                .takes_value(false)
            )
    }
}

/// Print out the supplied ip information.
fn print_ip_information(i: IpInformation) {
    println!("IP: {}", i.ip);
    println!("Country: {} ({})", i.country_name, i.country_code);
    println!("Region: {} ({})", i.region_name, i.region_code);
    println!("Continent: {} ({})", i.continent_name, i.continent_code);
    println!(
        "City: {} ({}) ({})", i.city_name, i.postal_code.unwrap_or_else(|| String::from("-")),
        i.postal_confidence.unwrap_or_else(|| String::from("-"))
    );
    println!("Metro code: {}", i.metro_code.unwrap_or_else(|| String::from("-")));
    println!("Lat/Long: {}/{} (Accuracy: {}km)", i.latitude, i.longitude, i.accuracy_radius);
}