use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;

use crate::utils::str_to_utc_datetime;

pub fn parse_expiration_date(whois_info: &str) -> Option<String> {
    let lines = whois_info.lines();

    for line in lines {
        let line_trimmed = line.trim();

        if line_trimmed.starts_with("Registry Expiry Date:") {
            let re = Regex::new(r"\s*Registry Expiry Date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                let datetime_utc = result.parse::<DateTime<Utc>>().unwrap();
                return Some(datetime_utc.to_rfc3339());
            }
            continue;
        } else if line_trimmed.starts_with("Expiry date:") {
            let re = Regex::new(r"\s*Expiry date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                return str_to_utc_datetime(caps.get(1).unwrap().as_str());
            }
            continue;
        } else if line_trimmed.starts_with("Expire Date:") {
            let re = Regex::new(r"\s*Expire Date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                return str_to_utc_datetime(caps.get(1).unwrap().as_str());
            }
            continue;
        } else if line_trimmed.starts_with("expires:") {
            let re = Regex::new(r"\s*expires:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                return str_to_utc_datetime(caps.get(1).unwrap().as_str());
            }
            continue;
        } else if line_trimmed.starts_with("Expiration date:") {
            let re = Regex::new(r"\s*Expiration date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let naive_datetime = NaiveDateTime::parse_from_str(
                    caps.get(1).unwrap().as_str(),
                    "%d.%m.%Y %H:%M:%S",
                )
                .unwrap();
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                return Some(datetime_utc.to_rfc3339());
            }
            continue;
        } else if line_trimmed.starts_with("paid-till:") {
            let re = Regex::new(r"\s*paid-till:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                let datetime_utc = result.parse::<DateTime<Utc>>().unwrap();
                return Some(datetime_utc.to_rfc3339());
            }
            continue;
        } else if line_trimmed.starts_with("validity:") {
            let re = Regex::new(r"\s*validity:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                return str_to_utc_datetime(caps.get(1).unwrap().as_str());
            }
            continue;
        }
    }

    None
}
