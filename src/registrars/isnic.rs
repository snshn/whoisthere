// ISNIC: .is

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

use crate::DomainProps;

pub fn parse_isnic_registrar_domain_whois_info<'a>(whois_info: &'a str) -> DomainProps<'a> {
    let mut domain_props = DomainProps {
        domain_name: "",
        is_registered: None,
        expiry_date: None,
        registrar: None,
    };

    let lines = whois_info.lines();

    for line in lines {
        if line.starts_with("% No entries found for query \"") && line.ends_with("\".") {
            domain_props.is_registered = Some(false);
            break;
        }

        if line.starts_with("expires:") {
            let re = Regex::new(r"expires:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let naive_date =
                    NaiveDate::parse_from_str(caps.get(1).unwrap().as_str(), "%B %d %Y").unwrap();
                let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                domain_props.expiry_date = Some(datetime_utc.to_rfc3339());
                domain_props.is_registered = Some(true);
            }
            continue;
        }
    }

    return domain_props;
}
