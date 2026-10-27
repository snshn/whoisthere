// JPRS: .jp

use super::util::{date_to_rfc3339, value_after};
use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_jprs_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Jprs),
        ..Default::default()
    };

    for line in whois_info.lines() {
        if line.is_empty() {
            continue;
        }

        if line == "No match!!" {
            domain_props.is_registered = Some(false);
            break;
        }

        if let Some(expires) = value_after(line, "[Expires on]") {
            domain_props.expiry_date = date_to_rfc3339(expires, "%Y/%m/%d");
            domain_props.is_registered = Some(true);
        } else if let Some(name) = value_after(line, "[Domain Name]") {
            domain_props.name = name;
        }
    }

    if domain_props.is_registered == Some(true) && domain_props.status.is_none() {
        domain_props.status = Some(DomainStatus::Active);
    }

    domain_props
}
