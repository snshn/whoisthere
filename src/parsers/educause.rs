// EDUCAUSE: .edu

use super::util::{date_to_rfc3339, value_after};
use crate::{DomainProps, WhoisService};

pub fn parse_educause_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Educause),
        ..Default::default()
    };

    for line in whois_info.lines() {
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("NO MATCH:") {
            domain_props.is_registered = Some(false);
            domain_props.name = rest.trim();
            break;
        }

        if let Some(expires) = value_after(line, "Domain expires:") {
            domain_props.expiry_date = date_to_rfc3339(expires, "%d-%B-%Y");
            domain_props.is_registered = Some(true);
        } else if let Some(name) = value_after(line, "Domain Name:") {
            domain_props.name = name;
        }
    }

    domain_props
}
