// RNIDS: .rs

use super::util::{datetime_to_rfc3339, value_after};
use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_rnids_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Rnids),
        ..Default::default()
    };

    for line in whois_info.lines() {
        if line.is_empty() {
            continue;
        }

        if line == "%ERROR:103: Domain is not registered" {
            domain_props.is_registered = Some(false);
            break;
        }

        if let Some(registrar) = value_after(line, "Registrar:") {
            domain_props.registrar = Some(registrar);
        } else if let Some(expires) = value_after(line, "Expiration date:") {
            domain_props.expiry_date = datetime_to_rfc3339(expires, "%d.%m.%Y %H:%M:%S");
            domain_props.is_registered = Some(true);
        } else if let Some(name) = value_after(line, "Domain name:") {
            domain_props.name = name;
        } else if value_after(line, "Domain status:").is_some_and(|s| s.starts_with("Active")) {
            domain_props.status = Some(DomainStatus::Active);
        }
    }

    domain_props
}
