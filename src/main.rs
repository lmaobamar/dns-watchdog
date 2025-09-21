use clap::Command;
use clap::{Arg, ArgGroup};
use cloudflare::endpoints::dns::dns;
use cloudflare::framework::auth::Credentials;
use cloudflare::framework::client::blocking_api::HttpApiClient;
use cloudflare::framework::client::ClientConfig;
use cloudflare::framework::Environment;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Command::new("dns-watchdog")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Dynamic IP updater for Cloudflare DNS")
        .arg(Arg::new("email")
            .long("email")
            .help("Email address associated with your account")
            .requires("auth-key"))
        .arg(Arg::new("auth-key")
            .long("auth-key")
            .env("CF_RS_AUTH_KEY")
            .help("API key generated on the \"My Account\" page")
            .requires("email"))
        .arg(Arg::new("auth-token")
            .long("auth-token")
            .env("CF_RS_AUTH_TOKEN")
            .help("API token generated on the \"My Account\" page")
            .conflicts_with_all(["email", "auth-key"]))
        .arg(Arg::new("zone-id")
            .long("zone-id")
            .env("CF_RS_ZONE_ID")
            .help("Zone ID of the DNS record to update")
            .required(true))
        .arg(Arg::new("record-id")
            .long("record-id")
            .env("CF_RS_RECORD_ID")
            .help("Record ID of the DNS record to update")
            .required(true))
        .group(ArgGroup::new("auth")
            .args(["email", "auth-key", "auth-token"])
            .multiple(true)
            .required(true))
        .arg_required_else_help(true);
    
    let mut matches = cli.clone().get_matches();
    let email = matches.remove_one::<String>("email");
    let key = matches.remove_one::<String>("auth-key");
    let token = matches.remove_one::<String>("auth-token");
    let environment = Environment::Production;
    
    let credentials: Credentials = if let Some(key) = key {
        Credentials::UserAuthKey {
            email: email.unwrap(),
            key,
        }
    } else if let Some(token) = token {
        Credentials::UserAuthToken { token }
    } else {
        panic!("Either API token or API key + email pair must be provided")
    };

    let api_client = HttpApiClient::new(credentials, ClientConfig::default(), environment)?;
    let zone_id = matches.remove_one::<String>("zone-id").unwrap();
    let record_id = matches.remove_one::<String>("record-id").unwrap();

    println!("Validating DNS record {record_id} in zone {zone_id}...");
    let init_list_endpoint = dns::ListDnsRecords {
        zone_identifier: &zone_id,
        params: dns::ListDnsRecordsParams {
            per_page: Some(100),
            page: Some(1),
            ..Default::default()
        },
    };
    let init_list_response = api_client.request(&init_list_endpoint)?;
    let init_records = init_list_response.result;
    let initial_record = init_records.iter().find(|r| r.id == record_id);
    if initial_record.is_none() {
        eprintln!("Invalid record. Is your Record ID correct?");
        std::process::exit(1);
    }
    let initial_record = initial_record.unwrap();
    match &initial_record.content {
        dns::DnsContent::A { .. } => {
            println!("Record OK: name={} ttl={} proxied={}", initial_record.name, initial_record.ttl, initial_record.proxied);
        }
        _ => {
            eprintln!("Invalid record. Record type should be A");
            std::process::exit(1);
        }
    }

    println!("Starting dns-watchdog loop. Interval: 10s");
    loop {
        let ip_text = reqwest::blocking::get("https://api.ipify.org/")?.text()?;
        let current_ip: Ipv4Addr = ip_text.trim().parse()?;
        println!("Fetched external IP: {current_ip}");

        let list_endpoint = dns::ListDnsRecords {
            zone_identifier: &zone_id,
            params: dns::ListDnsRecordsParams {
                per_page: Some(100),
                page: Some(1),
                ..Default::default()
            },
        };
        let list_response = api_client.request(&list_endpoint)?;
        let records = list_response.result;
        println!("Retrieved {} DNS records", records.len());

        if let Some(record) = records.iter().find(|r| r.id == record_id) {
            println!("Target record: id={} name={} ttl={} proxied={}", record.id, record.name, record.ttl, record.proxied);
            match &record.content {
                dns::DnsContent::A { content: existing_ip } => {
                    if existing_ip == &current_ip {
                        println!("No change needed. DNS already points to {existing_ip}");
                    } else {
                        println!("IP change detected: {existing_ip} -> {current_ip}. Updating record...");
                        let update_endpoint = dns::UpdateDnsRecord {
                            zone_identifier: &zone_id,
                            identifier: &record_id,
                            params: dns::UpdateDnsRecordParams {
                                name: &record.name,
                                content: dns::DnsContent::A { content: current_ip },
                                proxied: Some(record.proxied),
                                ttl: Some(record.ttl),
                            },
                        };
                        let _update_response = api_client.request(&update_endpoint)?;
                        println!("Update successful for record {} now pointing to {current_ip}", record.name);
                    }
                }
                other => {
                    println!("Record content type is not A (found {:?}). Skipping update.", other);
                }
            }
        } else {
            println!("Record with id {record_id} not found in zone. Will retry next cycle.");
        }

        thread::sleep(Duration::from_secs(10));
    }
}

//nya :3 adigato
