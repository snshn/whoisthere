use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

pub struct DomainProps {
    pub domain_name: String,
    pub expiration_date: String,
    pub registrar: Option<String>,
    pub is_registered: bool,
    pub is_under_grace_period: bool,
}

pub fn parse_info(domain_name: &str, whois_info: &str) -> DomainProps {
    let mut whois_data = DomainProps {
        domain_name: String::from(domain_name),
        expiration_date: String::new(),
        registrar: None,
        is_registered: false,
        is_under_grace_period: false,
    };

    let lines = whois_info.lines();
    for line in lines {
        let line = line.trim();

        // Determine if domain is registered
        if line.starts_with("Domain not found.")
            || line.starts_with("Domain not registered.")
            || line.starts_with("No match for")
            || line.starts_with("% No entries found for query")
        {
            break;
        }

        // Parse expiration date
        if line.starts_with("Registry Expiry Date:") {
            let re = Regex::new(r"Registry Expiry Date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                let datetime_utc = result.parse::<DateTime<Utc>>().unwrap();
                whois_data.is_registered = true;
                whois_data.expiration_date = format!("{:?}", datetime_utc);
            }
            continue;
        } else if line.starts_with("Expiry date:") {
            let re = Regex::new(r"Expiry date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let naive_date =
                    NaiveDate::parse_from_str(caps.get(1).unwrap().as_str(), "%d-%B-%Y").unwrap();
                let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                whois_data.is_registered = true;
                whois_data.expiration_date = format!("{:?}", datetime_utc);
            }
            continue;
        } else if line.starts_with("expires:") {
            let re = Regex::new(r"expires:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let naive_date =
                    NaiveDate::parse_from_str(caps.get(1).unwrap().as_str(), "%B %d %Y").unwrap();
                let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                whois_data.is_registered = true;
                whois_data.expiration_date = format!("{:?}", datetime_utc);
            }
            continue;
        } else if line.starts_with("Expiration date:") {
            let re = Regex::new(r"Expiration date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let naive_datetime = NaiveDateTime::parse_from_str(
                    caps.get(1).unwrap().as_str(),
                    "%d.%m.%Y %H:%M:%S",
                )
                .unwrap();
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                whois_data.is_registered = true;
                whois_data.expiration_date = format!("{:?}", datetime_utc);
            }
            continue;
        } else if line.starts_with("paid-till:") {
            let re = Regex::new(r"paid-till:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                let datetime_utc = result.parse::<DateTime<Utc>>().unwrap();
                whois_data.is_registered = true;
                whois_data.expiration_date = format!("{:?}", datetime_utc);
            }
            continue;
        }

        // Parse status
        if line.starts_with("Domain Status:") {
            let re = Regex::new(r"Domain Status:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                if result == "redemptionPeriod https://icann.org/epp#redemptionPeriod" {
                    whois_data.is_under_grace_period = true;
                }
            }
            continue;
        }

        // Parse registrar name
        if line.starts_with("Registrar:") || line.starts_with("registrar:") {
            let re = Regex::new(r"(?i)Registrar:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                whois_data.registrar = Some(result.to_string());
            }
            continue;
        }
    }

    // TODO: throw errors instead of simply returning a struct

    return whois_data;
}
