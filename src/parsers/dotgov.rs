// DOTGOV: .gov

use regex::Regex;

use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_dotgov_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Dotgov),
        ..Default::default()
    };

    let lines = whois_info.lines();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        if line.starts_with("No match for \"") && line.ends_with("\".") {
            domain_props.is_registered = Some(false);

            // Parse domain name while we're here
            let re = Regex::new(r####"No match for "(.*)"."####).unwrap();
            for caps in re.captures_iter(line) {
                domain_props.name = caps.get(1).unwrap().as_str();
            }

            break;
        }

        domain_props.is_registered = Some(true);

        let line_trimmed = line.trim();

        // Parse domain name
        if line_trimmed.starts_with("Domain Name: ") {
            let re = Regex::new(r"Domain Name:\s+(.*)").unwrap();
            for caps in re.captures_iter(line_trimmed) {
                domain_props.name = caps.get(1).unwrap().as_str();
            }
            continue;
        }

        // Parse domain status
        if line_trimmed.starts_with("Status: ") {
            let re = Regex::new(r"Status:\s+(.*)").unwrap();
            for caps in re.captures_iter(line_trimmed) {
                let domain_status_value = caps.get(1).unwrap().as_str();
                let domain_status_value = caps.get(1).unwrap().as_str();
                if domain_status_value.starts_with("ACTIVE") {
                    domain_props.status = Some(DomainStatus::Active);
                }
            }
            continue;
        }
    }

    domain_props
}
