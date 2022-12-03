// TCINET: .ru

use chrono::{DateTime, Utc};
use regex::Regex;

use crate::DomainProps;

pub fn parse_tcinet_registrar_domain_whois_info<'a>(whois_info: &'a str) -> DomainProps<'a> {
    let mut domain_props = DomainProps {
        domain_name: "",
        is_registered: None,
        expiration_date: None,
        registrar: None,
    };

    let lines = whois_info.lines();

    for line in lines {
        if line == "No entries found for the selected source(s)." {
            domain_props.is_registered = Some(false);
            break;
        }

        let line_trimmed = line.trim();

        if line_trimmed.starts_with("paid-till:") {
            let re = Regex::new(r"paid-till:\s+(.*)").unwrap();
            for caps in re.captures_iter(line_trimmed) {
                let result = caps.get(1).unwrap().as_str();
                let datetime_utc = result.parse::<DateTime<Utc>>().unwrap();
                domain_props.expiration_date = Some(datetime_utc.to_rfc3339());
                domain_props.is_registered = Some(true);
            }
            continue;
        }

        if line_trimmed.starts_with("registrar:") {
            let re = Regex::new(r"registrar:\s+(.*)").unwrap();
            // TODO: scan following lines, use struct { name, url }
            for caps in re.captures_iter(line_trimmed) {
                let result = caps.get(1).unwrap().as_str();
                domain_props.registrar = Some(result);
            }
            continue;
        }
    }

    return domain_props;
}
