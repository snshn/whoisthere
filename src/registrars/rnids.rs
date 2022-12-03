// RNIDS: .rs

use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;

use crate::{DomainPropStatus, DomainProps};

pub fn parse_rnids_registrar_domain_whois_info<'a>(
    domain_name: &'a str,
    whois_info: &'a str,
) -> DomainProps<'a> {
    let mut domain_props = DomainProps {
        domain_name: domain_name,
        is_registered: None,
        expiration_date: None,
        registrar: None,
        status: DomainPropStatus::Unknown,
    };

    let lines = whois_info.lines();

    for line in lines {
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
                domain_props.expiration_date = Some(datetime_utc.to_rfc3339());
                domain_props.is_registered = Some(true);
            }
            continue;
        }
    }

    return domain_props;
}
