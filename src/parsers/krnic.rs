// KRNIC: .kr

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

use crate::{DomainProps, WhoisService};

pub fn parse_krnic_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Krnic),
        ..Default::default()
    };

    let lines = whois_info.lines();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        if line == "The requested domain was not found in the Registry or Registrar’s WHOIS Server."
        {
            domain_props.is_registered = Some(false);
            break;
        }

        // Parse domain name
        if line.starts_with("Domain Name") {
            let re = Regex::new(r"Domain Name\s+:\s(.*)").unwrap();
            for caps in re.captures_iter(line) {
                domain_props.name = caps.get(1).unwrap().as_str();
            }
            continue;
        }

        if line.starts_with("Expiration Date") {
            let re = Regex::new(r"Expiration Date\s+:\s(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let naive_date =
                    NaiveDate::parse_from_str(caps.get(1).unwrap().as_str(), "%Y. %m. %d.")
                        .unwrap();
                let naive_datetime: NaiveDateTime = naive_date.and_hms_opt(0, 0, 0).unwrap();
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                domain_props.expiry_date = Some(datetime_utc.to_rfc3339());
                domain_props.is_registered = Some(true);
            }
            continue;
        }
    }

    domain_props
}
