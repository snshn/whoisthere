// ISNIC: .is

use super::util::{between, date_to_rfc3339, value_after};
use crate::{DomainProps, WhoisService};

pub fn parse_isnic_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Isnic),
        ..Default::default()
    };

    for line in whois_info.lines() {
        if line.is_empty() {
            continue;
        }

        if let Some(name) = between(line, "% No entries found for query \"", "\".") {
            domain_props.is_registered = Some(false);
            domain_props.name = name;
            break;
        }

        if let Some(expires) = value_after(line, "expires:") {
            domain_props.expiry_date = date_to_rfc3339(expires, "%B %d %Y");
            domain_props.is_registered = Some(true);
        } else if let Some(name) = value_after(line, "domain:") {
            domain_props.name = name;
        }
    }

    domain_props
}
