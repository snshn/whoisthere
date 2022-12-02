mod parsers;
pub mod utils;

use crate::parsers::expiration_date::parse_expiration_date;
use crate::parsers::registrar::parse_registrar;
use crate::parsers::status::parse_status;

#[derive(Debug, Eq, PartialEq)]
pub enum DomainPropStatus {
    Unknown,
    Unregistered,
    Registered,
    GracePeriod,
}
pub struct DomainProps<'t> {
    pub domain_name: &'t str,
    pub expiration_date: Option<String>,
    pub registrar: Option<&'t str>,
    pub status: DomainPropStatus,
}

impl DomainProps<'_> {
    pub fn is_registered(self: &Self) -> bool {
        self.status != DomainPropStatus::Unregistered && self.status != DomainPropStatus::Unknown
    }

    pub fn is_under_grace_period(self: &Self) -> bool {
        self.status == DomainPropStatus::GracePeriod
    }
}

pub fn parse_info<'t>(domain_name: &'t str, whois_info: &'t str) -> DomainProps<'t> {
    let mut whois_data = DomainProps {
        domain_name: domain_name,
        expiration_date: None,
        registrar: None,
        status: DomainPropStatus::Unknown,
    };

    // Parse status
    whois_data.status = parse_status(whois_info);

    if whois_data.status != DomainPropStatus::Unregistered {
        // Parse expiration date
        if let Some(expiration_date) = parse_expiration_date(whois_info) {
            whois_data.expiration_date = Some(expiration_date);

            if whois_data.status == DomainPropStatus::Unknown {
                whois_data.status = DomainPropStatus::Registered;
            }
        }

        // Parse registrar name
        whois_data.registrar = parse_registrar(whois_info);
    }

    // TODO: throw errors instead of simply returning a struct

    return whois_data;
}
