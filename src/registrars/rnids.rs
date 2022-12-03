// RNIDS: .rs

use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;

use crate::DomainProps;

pub fn parse_rnids_registrar_domain_whois_info<'a>(whois_info: &'a str) -> DomainProps<'a> {
    let mut domain_props = DomainProps {
        domain_name: "",
        is_registered: None,
        expiry_date: None,
        registrar: None,
    };

    let lines = whois_info.lines();

    for line in lines {
        if line == "" {
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
                domain_props.domain_name = caps.get(1).unwrap().as_str();
            }
            continue;
        }
    }

    return domain_props;
}
