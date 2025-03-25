// ISNIC: .is

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

use crate::{DomainProps, WhoisService};

pub fn parse_isnic_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Isnic),
        ..Default::default()
    };

    let lines = whois_info.lines();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        if line.starts_with("% No entries found for query \"") && line.ends_with("\".") {
            domain_props.is_registered = Some(false);

            // Parse domain name while we're here
            let re = Regex::new(r####"% No entries found for query "(.*)"."####).unwrap();
            for caps in re.captures_iter(line) {
                domain_props.name = caps.get(1).unwrap().as_str();
            }

            break;
        }

        if line.starts_with("expires:") {
            let re = Regex::new(r"expires:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let naive_date =
                    NaiveDate::parse_from_str(caps.get(1).unwrap().as_str(), "%B %d %Y").unwrap();
                let naive_datetime: NaiveDateTime = naive_date.and_hms_opt(0, 0, 0).unwrap();
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                domain_props.expiry_date = Some(datetime_utc.to_rfc3339());
                domain_props.is_registered = Some(true);
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
    }

    domain_props
}
