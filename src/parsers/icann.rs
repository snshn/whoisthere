// ICANN: .com

use chrono::{DateTime, Utc};
use regex::Regex;

use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_icann_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Icann),
        ..Default::default()
    };

    let lines = whois_info.lines();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        if line == "Domain not found." {
            domain_props.is_registered = Some(false);
            break;
        }
        if line.starts_with("No match for domain \"") && line.ends_with("\".") {
            domain_props.is_registered = Some(false);

            // Parse domain name while we're here
            let re = Regex::new(r####"No match for domain "(.*)"."####).unwrap();
            for caps in re.captures_iter(line) {
                domain_props.name = caps.get(1).unwrap().as_str();
            }

            break;
        }

        let line_trimmed = line.trim();

        if line_trimmed.starts_with("Registry Expiry Date:") {
            let re = Regex::new(r"Registry Expiry Date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line_trimmed) {
                let result = caps.get(1).unwrap().as_str();
                let datetime_utc = result.parse::<DateTime<Utc>>().unwrap();
                domain_props.expiry_date = Some(datetime_utc.to_rfc3339());
                domain_props.is_registered = Some(true);
            }
            continue;
        }

        if line_trimmed.starts_with("Registrar:") {
            let re = Regex::new(r"Registrar:\s+(.*)").unwrap();
            // TODO: scan following lines, use struct { name, url }
            for caps in re.captures_iter(line_trimmed) {
                let result = caps.get(1).unwrap().as_str();
                domain_props.registrar = Some(result);
            }
            continue;
        }

        // Parse domain name
        if line_trimmed.starts_with("Domain Name: ") {
            let re = Regex::new(r"Domain Name:\s+(.*)").unwrap();
            for caps in re.captures_iter(line_trimmed) {
                domain_props.name = caps.get(1).unwrap().as_str();
            }
            continue;
        }

        // Parse domain status
        if line_trimmed.starts_with("Domain Status: ") {
            let re = Regex::new(r"Domain Status:\s+(.*)").unwrap();
            for caps in re.captures_iter(line_trimmed) {
                let domain_status_value = caps.get(1).unwrap().as_str();
                if domain_status_value.starts_with("redemptionPeriod") {
                    domain_props.status = Some(DomainStatus::ExpiredRedemptionPeriod);
                } /*else if domain_status_value.starts_with("clientTransferProhibited")
                {
                domain_props.status = Some(DomainStatus::Registered);
                }*/
            }
            continue;
        }

        if domain_props.status.is_none() {
            domain_props.status = Some(DomainStatus::Active);
        }
    }

    domain_props
}
