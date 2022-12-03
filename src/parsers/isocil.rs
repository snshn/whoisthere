// ISOC-IL: .il

use regex::Regex;

use crate::{DomainProps, WhoisService};

pub fn parse_isocil_domain_whois_info<'a>(whois_info: &'a str) -> DomainProps<'a> {
    let mut domain_props = DomainProps {
        domain_name: "",
        whois_service: Some(WhoisService::IsocIl),
        is_registered: None,
        expiry_date: None,
        registrar: None,
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
        if line == "" {
            continue;
        }

        // Parse domain name
        if line.starts_with("domain:") {
            let re = Regex::new(r"domain:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                domain_props.domain_name = caps.get(1).unwrap().as_str();
            }
            continue;
        }
    }

    return domain_props;
}
