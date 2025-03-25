// ISOC-IL: .il

use regex::Regex;

use crate::{DomainProps, WhoisService};

pub fn parse_isocil_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::IsocIl),
        ..Default::default()
    };

    let lines = whois_info.lines();

    // Domain not registered, return basic info
    if lines.clone().count() == 15 {
        domain_props.is_registered = Some(false);
        return domain_props;
    } else {
        domain_props.is_registered = Some(true);
    }

    for line in lines {
        if line.is_empty() {
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
