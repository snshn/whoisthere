// RNIDS: .rs

use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;

use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_rnids_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Rnids),
        ..Default::default()
    };

    let lines = whois_info.lines();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        if line == "%ERROR:103: Domain is not registered" {
            domain_props.is_registered = Some(false);
            break;
        }

        if line.starts_with("Registrar:") {
            let re = Regex::new(r"Registrar:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                domain_props.registrar = Some(result);
            }
            continue;
        }

        if line.starts_with("Expiration date:") {
            let re = Regex::new(r"Expiration date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let naive_datetime = NaiveDateTime::parse_from_str(
                    caps.get(1).unwrap().as_str(),
                    "%d.%m.%Y %H:%M:%S",
                )
                .unwrap();
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                domain_props.expiry_date = Some(datetime_utc.to_rfc3339());
                domain_props.is_registered = Some(true);
            }
            continue;
        }

        // Parse domain name
        if line.starts_with("Domain name: ") {
            let re = Regex::new(r"Domain name:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                domain_props.name = caps.get(1).unwrap().as_str();
            }
            continue;
        }

        // Parse domain status
        if line.starts_with("Domain status: ") {
            let re = Regex::new(r"Domain status:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let domain_status_value = caps.get(1).unwrap().as_str();
                if domain_status_value.starts_with("Active") {
                    domain_props.status = Some(DomainStatus::Active);
                }
            }
            continue;
        }
    }

    domain_props
}
