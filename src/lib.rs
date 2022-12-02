mod parsers;
pub mod utils;

use crate::parsers::expiration_date::parse_expiration_date;
use crate::parsers::registrar::parse_registrar;
use crate::parsers::status::parse_status;

#[derive(Debug, Eq, PartialEq)]
pub enum DomainPropStatusFlag {
    Unknown,
    Unregistered,
    Registered,
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
    pub status: DomainPropStatus<'t>,
}

impl DomainProps<'_> {
    pub fn is_registered(self: &Self) -> bool {
        self.status.flag != DomainPropStatusFlag::Unregistered
            && self.status.flag != DomainPropStatusFlag::Unknown
    }

    pub fn is_under_grace_period(self: &Self) -> bool {
        self.status.flag == DomainPropStatusFlag::GracePeriod
    }
}

pub fn parse_info<'t>(domain_name: &'t str, whois_info: &'t str) -> DomainProps<'t> {
    let mut whois_data = DomainProps {
        domain_name: domain_name,
        expiration_date: None,
        registrar: None,
        status: DomainPropStatus {
            flag: DomainPropStatusFlag::Unknown,
            url: None,
        },
    };

    // Parse status
    whois_data.status = parse_status(whois_info);

    if whois_data.status.flag == DomainPropStatusFlag::Unregistered {
        return whois_data;
    }

    // Parse expiration date
    whois_data.expiration_date = parse_expiration_date(whois_info);
    if let Some(_) = whois_data.expiration_date {
        // whois_data.is_registered = true;
        if whois_data.status.flag == DomainPropStatusFlag::Unknown {
            whois_data.status.flag = DomainPropStatusFlag::Registered;
        }
    }

    // Parse registrar name
    whois_data.registrar = parse_registrar(whois_info);

    // TODO: throw errors instead of simply returning a struct

    return whois_data;
}
