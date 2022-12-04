// JPRS: .jp

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

use crate::{DomainProps, WhoisService};

pub fn parse_jprs_domain_whois_info<'a>(whois_info: &'a str) -> DomainProps<'a> {
    let mut domain_props = DomainProps {
        domain_name: "",
        whois_service: Some(WhoisService::Jprs),
        is_registered: None,
        expiry_date: None,
        registrar: None,
    };

    let lines = whois_info.lines();

    for line in lines {
        if line == "" {
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
                let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
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
                domain_props.domain_name = caps.get(1).unwrap().as_str();
            }
            continue;
        }
    }

    return domain_props;
}
