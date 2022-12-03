mod parsers;
mod registrars;
pub mod utils;

use crate::parsers::expiration_date::parse_expiration_date;
use crate::parsers::registrar::parse_registrar;
use crate::parsers::registration::parse_is_not_registered;
use crate::parsers::status::parse_status;
use crate::registrars::dotgov::parse_dotgov_domain_whois_info;

#[derive(Debug, Eq, PartialEq)]
pub enum DomainPropStatus {
    Unknown,
    Active,
    ClientTransferProhibited,
    RedemptionPeriod,
}
pub struct DomainProps<'t> {
    pub domain_name: &'t str,
    pub is_registered: Option<bool>,
    pub expiration_date: Option<String>,
    pub registrar: Option<&'t str>,
    pub status: DomainPropStatus,
}

impl DomainProps<'_> {
    pub fn is_under_grace_period(self: &Self) -> bool {
        self.status == DomainPropStatus::RedemptionPeriod
    }
}

pub fn parse_info<'t>(domain_name: &'t str, whois_info: &'t str) -> DomainProps<'t> {
    if domain_name.ends_with(".gov") {
        return parse_dotgov_domain_whois_info(domain_name, whois_info);
    }

    let mut whois_data = DomainProps {
        domain_name: domain_name,
        is_registered: None,
        expiration_date: None,
        registrar: None,
        status: DomainPropStatus::Unknown,
    };

    // Check if not registered first
    if parse_is_not_registered(whois_info) {
        whois_data.is_registered = Some(false);
    } else {
        // Parse status
        // whois_data.status = parse_status(whois_info);
        // if whois_data.status == DomainPropStatus::Unknown {
        //     whois_data.is_registered = true;
        // }

        // Parse expiration date
        if let Some(expiration_date) = parse_expiration_date(whois_info) {
            whois_data.expiration_date = Some(expiration_date);
            whois_data.is_registered = Some(true);
        }

        // Parse registrar name
        whois_data.registrar = parse_registrar(whois_info);
    }

    // TODO: throw errors instead of simply returning a struct

    return whois_data;
}
