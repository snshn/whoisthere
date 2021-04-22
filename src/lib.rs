use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

pub struct DomainProps {
    pub domain_name: String,
    pub expiration_date: String,
    pub is_registered: bool,
    pub is_under_grace_period: bool,
}

pub fn parse_info(domain_name: &str, whois_info: &str) -> DomainProps {
    let mut whois_data = DomainProps {
        domain_name: String::from(domain_name),
        expiration_date: String::new(),
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
            break;
        }

        // Parse expiration date
        if line_trimmed.starts_with("Registry Expiry Date:") {
            let re = Regex::new(r"Registry Expiry Date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line_trimmed) {
                let result = caps.get(1).unwrap().as_str();
                let datetime_utc = result.parse::<DateTime<Utc>>().unwrap();
                whois_data.is_registered = true;
                whois_data.expiration_date = format!("{:?}", datetime_utc);
            }
            continue;
        } else if line_trimmed.starts_with("Expiry date:") {
            let re = Regex::new(r"Expiry date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line_trimmed) {
                let naive_date =
                    NaiveDate::parse_from_str(caps.get(1).unwrap().as_str(), "%d-%B-%Y").unwrap();
                let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                whois_data.is_registered = true;
                whois_data.expiration_date = format!("{:?}", datetime_utc);
            }
            continue;
        } else if line_trimmed.starts_with("expires:") {
            let re = Regex::new(r"expires:\s+(.*)").unwrap();
            for caps in re.captures_iter(line_trimmed) {
                let naive_date =
                    NaiveDate::parse_from_str(caps.get(1).unwrap().as_str(), "%B %d %Y").unwrap();
                let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                whois_data.is_registered = true;
                whois_data.expiration_date = format!("{:?}", datetime_utc);
            }
            continue;
        }
    }

    // TODO: parse more outputs (e.g. registrar)
    // TODO: throw errors instead of simply returning a struct

    return whois_data;
}

#[cfg(test)]
pub mod test;
