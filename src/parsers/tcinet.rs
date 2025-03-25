// TCINET: .ru

use chrono::{DateTime, Utc};
use regex::Regex;

use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_tcinet_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Tcinet),
        ..Default::default()
    };

    let lines = whois_info.lines();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        if line == "No entries found for the selected source(s)." {
            domain_props.is_registered = Some(false);
            break;
        }

        if line.starts_with("paid-till:") {
            let re = Regex::new(r"paid-till:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                let datetime_utc = result.parse::<DateTime<Utc>>().unwrap();
                domain_props.expiry_date = Some(datetime_utc.to_rfc3339());
                domain_props.is_registered = Some(true);
            }
            continue;
        }

        if line.starts_with("registrar:") {
            let re = Regex::new(r"registrar:\s+(.*)").unwrap();
            // TODO: scan following lines, use struct { name, url }
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                domain_props.registrar = Some(result);
            }
            continue;
        }

        // Parse domain name
        if line.starts_with("domain:") {
            let re = Regex::new(r"domain:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                domain_props.name = caps.get(1).unwrap().as_str();
            }
            continue;
        }

        // Parse domain status
        if line.starts_with("state:") {
            let re = Regex::new(r"state:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let domain_status_value = caps.get(1).unwrap().as_str();
                let domain_status_values: Vec<&str> = domain_status_value.split(", ").collect();
                if domain_status_values.contains(&"REGISTERED") {
                    domain_props.status = Some(DomainStatus::Active);
                }
            }
            continue;
        }
    }

    domain_props
}
