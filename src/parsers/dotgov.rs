// DOTGOV: .gov

use super::util::{between, value_after};
use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_dotgov_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Dotgov),
        ..Default::default()
    };

    for line in whois_info.lines() {
        if line.is_empty() {
            continue;
        }

        if let Some(name) = between(line, "No match for \"", "\".") {
            domain_props.is_registered = Some(false);
            domain_props.name = name;
            break;
        }

        domain_props.is_registered = Some(true);

        let line = line.trim();

        if let Some(name) = value_after(line, "Domain Name:") {
            domain_props.name = name;
        } else if value_after(line, "Status:").is_some_and(|s| s.starts_with("ACTIVE")) {
            domain_props.status = Some(DomainStatus::Active);
        }
    }

    domain_props
}
