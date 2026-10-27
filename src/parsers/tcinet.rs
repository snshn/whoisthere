// TCINET: .ru

use super::util::{rfc3339_to_rfc3339, value_after};
use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_tcinet_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Tcinet),
        ..Default::default()
    };

    for line in whois_info.lines() {
        if line.is_empty() {
            continue;
        }

        if line == "No entries found for the selected source(s)." {
            domain_props.is_registered = Some(false);
            break;
        }

        if let Some(expires) = value_after(line, "paid-till:") {
            domain_props.expiry_date = rfc3339_to_rfc3339(expires);
            domain_props.is_registered = Some(true);
        } else if let Some(registrar) = value_after(line, "registrar:") {
            // TODO: scan following lines, use struct { name, url }
            domain_props.registrar = Some(registrar);
        } else if let Some(name) = value_after(line, "domain:") {
            domain_props.name = name;
        } else if value_after(line, "state:")
            .is_some_and(|state| state.split(',').any(|s| s.trim() == "REGISTERED"))
        {
            domain_props.status = Some(DomainStatus::Active);
        }
    }

    domain_props
}
