// NIC-IT: .it

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_nicit_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::NicIt),
        ..Default::default()
    };

    let lines = whois_info.lines();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        // Parse name
        if line.starts_with("Domain: ") {
            let re = Regex::new(r"Domain:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                domain_props.name = caps.get(1).unwrap().as_str();
            }
            continue;
        }

        // Parse expiry date
        if line.starts_with("Expire Date:") {
            let re = Regex::new(r"Expire Date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                // TODO: find out what kind of time zone is used by this NIC
                let naive_date =
                    NaiveDate::parse_from_str(caps.get(1).unwrap().as_str(), "%Y-%m-%d").unwrap();
                let naive_datetime: NaiveDateTime = naive_date.and_hms_opt(0, 0, 0).unwrap();
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                domain_props.expiry_date = Some(datetime_utc.to_rfc3339());
                domain_props.is_registered = Some(true);
            }
            continue;
        }

        // Parse status
        if line.starts_with("Status: ") {
            let re = Regex::new(r"Status:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let domain_status_value = caps.get(1).unwrap().as_str();
                if domain_status_value == "ok" {
                    domain_props.status = Some(DomainStatus::Active);
                } else if domain_status_value == "AVAILABLE" {
                    domain_props.is_registered = Some(false);
                }
            }
            continue;
        }
    }

    domain_props
}
