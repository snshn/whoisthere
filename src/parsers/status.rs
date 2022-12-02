use regex::Regex;

use crate::{DomainPropStatus, DomainPropStatusFlag};

pub fn parse_status(whois_info: &str) -> DomainPropStatus {
    let mut status = DomainPropStatus {
        flag: DomainPropStatusFlag::Unknown,
        url: None,
    };

    let lines = whois_info.lines();

    for line in lines {
        let line_trimmed = line.trim();

        // Parse expiration date
        if line_trimmed.starts_with("Domain not found.")
            || line_trimmed.starts_with("Domain not registered.")
            || line_trimmed.starts_with("No match for")
            || line_trimmed.starts_with("% No entries found for query")
        {
            // Nothing to do, get out of the loop
            status.flag = DomainPropStatusFlag::Unregistered;
        }
    }

    let lines = whois_info.lines();

    for line in lines {
        let line_trimmed = line.trim();

        // Parse status
        if line_trimmed.starts_with("Domain Status:") {
            let re = Regex::new(r"\s*Domain Status:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                if result == "redemptionPeriod https://icann.org/epp#redemptionPeriod" {
                    status.flag = DomainPropStatusFlag::GracePeriod;
                    // TODO XXX FIXME
                    status.url = Some("https://icann.org/epp#redemptionPeriod");
                }
            }
            continue;
        }
    }

    status
}
