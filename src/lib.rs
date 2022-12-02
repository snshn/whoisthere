mod parsers;
pub mod utils;

use crate::parsers::expiration_date::parse_expiration_date;
use crate::parsers::is_registered::parse_is_registered;
use crate::parsers::registrar::parse_registrar;
use crate::parsers::status::parse_status;

#[derive(Debug, Eq, PartialEq)]
pub enum DomainPropStatusFlag {
    Unknown,
    GracePeriod,
}

pub struct DomainPropStatus<'t> {
    pub flag: DomainPropStatusFlag,
    pub url: Option<&'t str>,
}

pub struct DomainProps<'t> {
    pub domain_name: &'t str,
    pub expiration_date: Option<String>,
    pub registrar: Option<&'t str>,
    pub is_registered: bool,
    pub status: DomainPropStatus<'t>,
}

pub fn parse_info<'t>(domain_name: &'t str, whois_info: &'t str) -> DomainProps<'t> {
    let mut whois_data = DomainProps {
        domain_name: domain_name,
        expiration_date: None,
        registrar: None,
        is_registered: false,
        status: DomainPropStatus {
            flag: DomainPropStatusFlag::Unknown,
            url: None,
        },
    };

    // Determine if domain is registered
    if let Some(is_registered) = parse_is_registered(whois_info) {
        whois_data.is_registered = is_registered;

        if !is_registered {
            return whois_data;
        }
    }

    // Parse status
    whois_data.status = parse_status(whois_info);

    // Parse expiration date
    whois_data.expiration_date = parse_expiration_date(whois_info);
    if let Some(_) = whois_data.expiration_date {
        whois_data.is_registered = true;
    }

    // Parse registrar name
    whois_data.registrar = parse_registrar(whois_info);

    // TODO: throw errors instead of simply returning a struct

    return whois_data;
}
