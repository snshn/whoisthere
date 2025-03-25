// JPRS: .jp

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_jprs_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Jprs),
        ..Default::default()
    };

    let lines = whois_info.lines();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        if line == "No match!!" {
            domain_props.is_registered = Some(false);
            break;
        }

        if line.starts_with("[Expires on]") {
            let re = Regex::new(r"\[Expires on\]\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let naive_date =
                    NaiveDate::parse_from_str(caps.get(1).unwrap().as_str(), "%Y/%m/%d").unwrap();
                let naive_datetime: NaiveDateTime = naive_date.and_hms_opt(0, 0, 0).unwrap();
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                domain_props.expiry_date = Some(datetime_utc.to_rfc3339());
                domain_props.is_registered = Some(true);
            }
            continue;
        }

        // Parse domain name
        if line.starts_with("[Domain Name]") {
            let re = Regex::new(r"\[Domain Name\]\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                domain_props.name = caps.get(1).unwrap().as_str();
            }
            continue;
        }
    }

    if domain_props.is_registered.unwrap_or_default() && domain_props.status.is_none() {
        domain_props.status = Some(DomainStatus::Active);
    }

    domain_props
}
