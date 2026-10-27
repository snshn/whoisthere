// ISOC-IL: .il

use super::util::{date_to_rfc3339, value_after};
use crate::{DomainProps, WhoisService};

pub fn parse_isocil_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::IsocIl),
        // Unregistered domains get only the "%" comment banner, with no record
        is_registered: Some(false),
        ..Default::default()
    };

    for line in whois_info.lines() {
        // Contact and registrar objects follow the domain object and have their own
        // "changed:" etc. fields, so only take the first occurrence of each field
        if let Some(name) = value_after(line, "domain:") {
            if domain_props.name.is_empty() {
                domain_props.name = name;
                domain_props.is_registered = Some(true);
            }
        } else if let Some(validity) = value_after(line, "validity:") {
            if domain_props.expiry_date.is_none() {
                domain_props.expiry_date = date_to_rfc3339(validity, "%d-%m-%Y");
            }
        } else if let Some(registrar) = value_after(line, "registrar name:") {
            domain_props.registrar.get_or_insert(registrar);
        }
    }

    domain_props
}
