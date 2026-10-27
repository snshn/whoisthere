// KRNIC: .kr

use super::util::{date_to_rfc3339, padded_value};
use crate::{DomainProps, WhoisService};

pub fn parse_krnic_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Krnic),
        ..Default::default()
    };

    for line in whois_info.lines() {
        if line.is_empty() {
            continue;
        }

        if line == "The requested domain was not found in the Registry or Registrar’s WHOIS Server."
        {
            domain_props.is_registered = Some(false);
            break;
        }

        if let Some(name) = padded_value(line, "Domain Name") {
            domain_props.name = name;
        } else if let Some(agency) = padded_value(line, "Authorized Agency") {
            // "Gabia, Inc.(http://www.gabia.co.kr)"
            let name = agency.split_once("(http").map_or(agency, |(name, _)| name);
            domain_props.registrar = Some(name.trim_end());
        } else if let Some(expires) = padded_value(line, "Expiration Date") {
            domain_props.expiry_date = date_to_rfc3339(expires, "%Y. %m. %d.");
            domain_props.is_registered = Some(true);
        }
    }

    domain_props
}
