use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

pub struct DomainProps<'t> {
    pub domain_name: &'t str,
    pub expiration_date: Option<String>,
    pub registrar: Option<&'t str>,
    pub is_registered: bool,
    pub is_under_grace_period: bool,
}

pub fn parse_datetime(datetime: &str) -> Option<String> {
    let re_bdy = Regex::new(r"(January|February|March|April|May|June|July|August|September|October|November|December) \d{2} \d{4}").unwrap();
    let re_dby = Regex::new(r"\d{2}-(January|February|March|April|May|June|July|August|September|October|November|December)-\d{4}").unwrap();

    if re_bdy.is_match(datetime) {
        let naive_date = NaiveDate::parse_from_str(datetime, "%B %d %Y").unwrap();
        let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
        let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
        return Some(datetime_utc.to_rfc3339());
    } else if re_dby.is_match(datetime) {
        let naive_date = NaiveDate::parse_from_str(datetime, "%d-%B-%Y").unwrap();
        let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
        let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
        return Some(datetime_utc.to_rfc3339());
    }

    None
}

pub fn parse_info<'t>(domain_name: &'t str, whois_info: &'t str) -> DomainProps<'t> {
    let mut whois_data = DomainProps {
        domain_name: domain_name,
        expiration_date: None,
        registrar: None,
        is_registered: false,
        is_under_grace_period: false,
    };

    let lines = whois_info.lines();
    for line in lines {
        let line_trimmed = line.trim();

        // Determine if domain is registered
        if line_trimmed.starts_with("Domain not found.")
            || line_trimmed.starts_with("Domain not registered.")
            || line_trimmed.starts_with("No match for")
            || line_trimmed.starts_with("% No entries found for query")
        {
            // Nothing to do, get out of the loop
            break;
        }

        // Parse expiration date
        if line_trimmed.starts_with("Registry Expiry Date:") {
            let re = Regex::new(r"\s*Registry Expiry Date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                let datetime_utc = result.parse::<DateTime<Utc>>().unwrap();
                whois_data.is_registered = true;
                whois_data.expiration_date = Some(datetime_utc.to_rfc3339());
            }
            continue;
        } else if line_trimmed.starts_with("Expiry date:") {
            let re = Regex::new(r"\s*Expiry date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                whois_data.is_registered = true;
                whois_data.expiration_date = parse_datetime(caps.get(1).unwrap().as_str());
            }
            continue;
        } else if line_trimmed.starts_with("expires:") {
            let re = Regex::new(r"\s*expires:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                whois_data.is_registered = true;
                whois_data.expiration_date = parse_datetime(caps.get(1).unwrap().as_str());
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
                whois_data.is_registered = true;
                whois_data.expiration_date = Some(datetime_utc.to_rfc3339());
            }
            continue;
        } else if line_trimmed.starts_with("paid-till:") {
            let re = Regex::new(r"\s*paid-till:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                let datetime_utc = result.parse::<DateTime<Utc>>().unwrap();
                whois_data.is_registered = true;
                whois_data.expiration_date = Some(datetime_utc.to_rfc3339());
            }
            continue;
        }

        // Parse status
        if line_trimmed.starts_with("Domain Status:") {
            let re = Regex::new(r"\s*Domain Status:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                if result == "redemptionPeriod https://icann.org/epp#redemptionPeriod" {
                    whois_data.is_under_grace_period = true;
                }
            }
            continue;
        }

        // Parse registrar name
        if line_trimmed.starts_with("Registrar:") || line_trimmed.starts_with("registrar:") {
            let re = Regex::new(r"(?i)Registrar:\s+(.*)").unwrap();
            // TODO: scan following lines, use struct { name, url }
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                whois_data.registrar = Some(result);
            }
            continue;
        }
    }

    // TODO: throw errors instead of simply returning a struct

    return whois_data;
}
