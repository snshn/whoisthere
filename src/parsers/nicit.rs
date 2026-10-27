// NIC-IT: .it

use super::util::{date_to_rfc3339, value_after};
use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_nicit_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::NicIt),
        ..Default::default()
    };

    let mut section = "";

    for line in whois_info.lines() {
        if line.is_empty() {
            continue;
        }

        // Contact sections ("Registrant", "Registrar", …) are unindented headers
        // followed by indented fields
        if !line.starts_with(' ') && !line.contains(':') {
            section = line.trim();
            continue;
        }

        if line.starts_with(' ') {
            if section == "Registrar" {
                domain_props.registrar =
                    value_after(line.trim(), "Name:").or(domain_props.registrar);
            }
            continue;
        }

        if let Some(name) = value_after(line, "Domain:") {
            domain_props.name = name;
        } else if let Some(expires) = value_after(line, "Expire Date:") {
            // TODO: find out what kind of time zone is used by this NIC
            domain_props.expiry_date = date_to_rfc3339(expires, "%Y-%m-%d");
            domain_props.is_registered = Some(true);
        } else if let Some(status) = value_after(line, "Status:") {
            if status == "ok" {
                domain_props.status = Some(DomainStatus::Active);
            } else if status == "AVAILABLE" {
                domain_props.is_registered = Some(false);
            }
        }
    }

    domain_props
}
